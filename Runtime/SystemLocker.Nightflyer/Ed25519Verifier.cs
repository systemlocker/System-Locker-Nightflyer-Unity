// Vendored, dependency-free Ed25519 signature VERIFICATION for System Locker.
//
// Design notes:
//   - Verification only. The client never signs with this code, and every
//     input (public key, message, signature) is public, so the usual
//     constant-time requirements for secret handling do not apply here.
//   - Field arithmetic uses System.Numerics.BigInteger with explicit mod-p
//     reduction. The code is short and auditable at the cost of speed;
//     a verification takes a few milliseconds, which is irrelevant for
//     license checks.
//   - Strict decoding per RFC 8032 §5.1.7 guidance: non-canonical point
//     encodings and S >= L are rejected, which also blocks signature
//     malleability.
//
// Validated against the RFC 8032 test vectors.

using System;
using System.Numerics;
using System.Security.Cryptography;

namespace SystemLocker.Nightflyer
{
    /// <summary>Ed25519 (RFC 8032) public-key signature verification.</summary>
    internal static class Ed25519Verifier
    {
        private const int KeySize = 32;
        private const int SignatureSize = 64;

        // p = 2^255 - 19
        private static readonly BigInteger P = BigInteger.Subtract(BigInteger.Pow(2, 255), 19);

        // L = 2^252 + 27742317777372353535851937790883648493 (group order)
        private static readonly BigInteger L = BigInteger.Add(
            BigInteger.Pow(2, 252),
            BigInteger.Parse("27742317777372353535851937790883648493"));

        // d = -121665 / 121666 mod p
        private static readonly BigInteger D = BigInteger.ModPow(
            BigInteger.Multiply(-121665, BigInteger.ModPow(121666, P - 2, P)),
            1, P);

        // sqrt(-1) = 2^((p-1)/4) mod p
        private static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);

        // Base point B.
        private static readonly Point B = new(
            BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
            BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960"),
            BigInteger.One,
            BigInteger.Multiply(
                BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
                BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960")) % P);

        private static readonly Point Identity = new(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);

        /// <summary>Verifies a raw Ed25519 signature (R || s) over the message.</summary>
        public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message)
        {
            if (publicKey.Length != KeySize || signature.Length != SignatureSize)
            {
                return false;
            }

            Point a;
            if (!TryDecodePoint(publicKey, out a))
            {
                return false;
            }
            // A pinned key still needs to be a non-identity member of the prime
            // order subgroup. Without this check, a small-order public key can
            // make otherwise trivial signatures verify for arbitrary messages.
            if (a.Equals(Identity) || !ScalarMultiply(L, a).Equals(Identity))
            {
                return false;
            }

            Point r;
            if (!TryDecodePoint(signature.Slice(0, KeySize), out r))
            {
                return false;
            }
            if (!ScalarMultiply(L, r).Equals(Identity))
            {
                return false;
            }

            // S, little-endian, must be canonical (< L).
            BigInteger s = DecodeLittleEndian(signature.Slice(KeySize));
            if (s >= L || s < 0)
            {
                return false;
            }

            // h = SHA-512(R || A || M) mod L.
            byte[] hash;
            using (var sha512 = SHA512.Create())
            {
                sha512.TransformBlock(signature.Slice(0, KeySize).ToArray(), 0, KeySize, null, 0);
                sha512.TransformBlock(publicKey.ToArray(), 0, KeySize, null, 0);
                sha512.TransformFinalBlock(message.ToArray(), 0, message.Length);
                hash = sha512.Hash;
            }
            BigInteger h = BigInteger.Remainder(DecodeLittleEndian(hash), L);

            // Check [S]B == R + [h]A, i.e. [S]B + [h](-A) == R.
            Point negatedA = new(BigInteger.Negate(a.X).Mod(P), a.Y, a.Z, BigInteger.Negate(a.T).Mod(P));
            Point left = Add(ScalarMultiply(s, B), ScalarMultiply(h, negatedA));
            return left.Equals(r);
        }

        private static BigInteger DecodeLittleEndian(ReadOnlySpan<byte> bytes)
        {
            var littleEndian = new byte[bytes.Length + 1];
            bytes.CopyTo(littleEndian);
            return new BigInteger(littleEndian); // BigInteger(bool[], byte[]) ctor: little-endian, positive
        }

        internal static bool TryDecodePoint(ReadOnlySpan<byte> encoded, out Point point)
        {
            point = default;

            byte[] copy = encoded.ToArray();
            int signBit = copy[31] >> 7;
            copy[31] &= 0x7F;

            BigInteger y = DecodeLittleEndian(copy);
            if (y >= P)
            {
                return false; // non-canonical y
            }

            // x² = (y² − 1) / (d·y² + 1); recover the square root.
            BigInteger y2 = y * y % P;
            BigInteger u = (y2 - 1).Mod(P);
            BigInteger v = (MulD(y2) + 1).Mod(P);

            // candidate = u·v³·(u·v⁷)^((p−5)/8); the root is either candidate or candidate·sqrt(-1).
            BigInteger v3 = v * v % P * v % P;
            BigInteger v7 = v3 * v3 % P * v % P;
            BigInteger candidate = u * v3 % P * BigInteger.ModPow(u * v7 % P, (P - 5) / 8, P) % P;

            BigInteger x;
            BigInteger check = candidate * candidate % P * v % P;
            if (check == u)
            {
                x = candidate;
            }
            else if (check == (-u).Mod(P))
            {
                x = candidate * SqrtM1 % P;
            }
            else
            {
                return false; // not a square: invalid point encoding
            }

            if (x == 0 && signBit == 1)
            {
                return false; // sign bit set on x = 0: non-canonical
            }
            // The square root above yields an arbitrary root; the encoding's
            // sign bit selects the root whose parity matches it.
            bool xIsOdd = !x.IsEven;
            if ((signBit == 1) != xIsOdd)
            {
                x = (P - x).Mod(P);
            }

            point = new Point(x, y, BigInteger.One, x * y % P);
            return true;
        }

        private static BigInteger MulD(BigInteger y2) => BigInteger.Remainder(BigInteger.Multiply(D, y2), P);

        internal static Point Add(Point left, Point right)
        {
            // Extended homogeneous coordinates (RFC 8032 §5.1.4, unrolled dbl-2008-hwcd variant).
            // Every stored coordinate is normalized into [0, p): BigInteger's %
            // keeps the sign of the dividend, which would break equality.
            BigInteger a = ((left.Y - left.X) * (right.Y - right.X)).Mod(P);
            BigInteger b = ((left.Y + left.X) * (right.Y + right.X)).Mod(P);
            BigInteger c = (2 * left.T * right.T).Mod(P) * D % P;
            BigInteger d2 = (2 * left.Z * right.Z).Mod(P);
            BigInteger e = (b - a).Mod(P);
            BigInteger f = (d2 - c).Mod(P);
            BigInteger g = (d2 + c).Mod(P);
            BigInteger h = (b + a).Mod(P);
            return new Point(
                e * f % P,
                g * h % P,
                f * g % P,
                e * h % P);
        }

        internal static Point ScalarMultiply(BigInteger scalar, Point point)
        {
            Point result = new(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero); // identity
            Point addend = point;
            // Double-and-add, least-significant bit first.
            while (scalar > 0)
            {
                if (!scalar.IsEven)
                {
                    result = Add(result, addend);
                }
                addend = Add(addend, addend);
                scalar >>= 1;
            }
            return result;
        }

        /// <summary>A point in extended twisted-Edwards coordinates (X:Y:Z:T), T = XY/Z.</summary>
        internal readonly struct Point : IEquatable<Point>
        {
            public readonly BigInteger X;
            public readonly BigInteger Y;
            public readonly BigInteger Z;
            public readonly BigInteger T;

            public Point(BigInteger x, BigInteger y, BigInteger z, BigInteger t)
            {
                X = x; Y = y; Z = z; T = t;
            }

            public bool Equals(Point other)
            {
                // x1/z1 == x2/z2 and y1/z1 == y2/z2  ⟺  x1·z2 == x2·z1 and y1·z2 == y2·z1
                return (X * other.Z - other.X * Z).Mod(P).IsZero && (Y * other.Z - other.Y * Z).Mod(P).IsZero;
            }
        }
    }

    internal static class BigIntegerModExtension
    {
        /// <summary>Always-non-negative remainder (BigInteger.Remainder can be negative).</summary>
        public static BigInteger Mod(this BigInteger value, BigInteger modulus)
        {
            BigInteger remainder = BigInteger.Remainder(value, modulus);
            return remainder.Sign < 0 ? remainder + modulus : remainder;
        }
    }
}
