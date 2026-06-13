// Disambiguate the EC types from the BCL's System.Security.Cryptography.ECPoint
// (pulled in by implicit usings) — this package's group math is BouncyCastle's.
global using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;
global using BigInteger = Org.BouncyCastle.Math.BigInteger;
