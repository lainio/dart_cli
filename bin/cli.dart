import 'package:cryptography/cryptography.dart';
import 'package:dart_wot/dart_wot.dart' as wot;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

import 'package:basic_utils/basic_utils.dart';
import 'package:cbor/cbor.dart';

var cborKey =
    'pQECAyYgASFYIIcEZtPD-t7SgrBCqo8DmkzK-5hPRC7Agr9-4w2Egc3EIlggArnWSfgKmTTjWiOvtNu9Ck7jJDJpVJvff7CX_xQhzbk=';

Future<void> main() async {
  final Base64Codec base64 = const Base64Codec();

  base64.normalize(cborKey);
  print(cborKey);
  final ckey = base64.decode(cborKey);
  print(ckey);
  cborMy(ckey);

  // the private key
  ECPrivateKey? privateKey;

  final akp = CryptoUtils.generateEcKeyPair();
  //final pubKey = akp.publicKey as EcPublicKey;
  final pubKey = akp.publicKey as ECPublicKey;
//  final x = pubKey.x;
//  final y = pubKey.y;
  privateKey = akp.privateKey as ECPrivateKey;

  // some bytes to sign
  //final bytes = Uint8List(0);

  final url = 'My URL string...';
  //Convert the URL string to Uint8List
  final bytes = utf8.encode(url);

  // a suitable random number generator - create it just once and reuse
  final rand = Random.secure();
  final fortunaPrng = FortunaRandom()
    ..seed(KeyParameter(Uint8List.fromList(List<int>.generate(
      32,
      (_) => rand.nextInt(256),
    ))));

  // the ECDSA signer using SHA-256
  final signer = ECDSASigner(SHA256Digest())
    ..init(
      true,
      ParametersWithRandom(
        PrivateKeyParameter(privateKey),
        fortunaPrng,
      ),
    );

  // sign the bytes
  final ecSignature = signer.generateSignature(bytes) as ECSignature;

  // encode the two signature values in a common format
  // hopefully this is what the server expects
  final _ = ASN1Sequence(elements: [
    ASN1Integer(ecSignature.r),
    ASN1Integer(ecSignature.s),
  ]).encode();

  // and finally base 64 encode it
  //final signature = base64UrlEncode(encoded);

  ECSignature sig =
      CryptoUtils.ecSign(privateKey, bytes, algorithmName: 'SHA-256/ECDSA');
  final pem = CryptoUtils.encodeEcPublicKeyToPem(pubKey);
  //final der = CryptoUtils.Der
  final signature2 = CryptoUtils.ecSignatureToBase64(sig);
  print('signature2: $signature2');

  print('======&======');
  cborSample(pubKey);
}

Future<void> main4() async {
  final algorithm = AesGcm.with256bits();

  // Generate a random 256-bit secret key
  final secretKey = await algorithm.newSecretKey();

  // Generate a random 96-bit nonce.
  final nonce = algorithm.newNonce();

  // Encrypt
  final clearText = [1, 2, 3];
  final secretBox = await algorithm.encrypt(
    clearText,
    secretKey: secretKey,
    nonce: nonce,
  );
  print('Ciphertext: ${secretBox.cipherText}');
  print('MAC: ${secretBox.mac}');

  print('=============');
  await main2();
}

Future<void> main2() async {
  final algorithm = Ed25519();

  // Generate a key pair
  final keyPair = await algorithm.newKeyPair();
  final e = await keyPair.extractPrivateKeyBytes();
  print('privatekeybytes');
  print(e.toString());

  // Sign a message
  final message = <int>[1, 2, 3];
  final signature = await algorithm.sign(
    message,
    keyPair: keyPair,
  );
  print('Signature bytes: ${signature.bytes}');
  print('----');
  print('Public key: ${signature.publicKey.toString()}');
  print('----');

  // Anyone can verify the signature
  final isSignatureCorrect = await algorithm.verify(
    message,
    signature: signature,
  );
  print('signature: $isSignatureCorrect');
}

void cborMy(List<int> d) {
  final decoder = CborDecoder();
  decoder.cast();
  final cborData = cborDecode(d);
  print(cborData);
  //final siple = CborSimpleValue(cborData);
  final siple = CborValue(cborData);
  print(siple);

  final eCoseK = wot.EncryptedCoseKey.fromValue(cborData);
  print(eCoseK);
}

int cborSample(ECPublicKey ecPublicKey) {
  final key = wot.CoseKey(
      keyType: wot.KeyType.ec2,
      algorithm: wot.Algorithm.es256,
      keyId: [ // todo: how we going to name our keys
        0xDF,
        0xD1,
        0xAA,
        0x97
      ],
      parameters: {
        // field "k" (the key itself)
        -1: CborInt(BigInt.one),
        -2: CborBigInt(ecPublicKey.Q!.x!.toBigInteger()!),
        -3: CborBigInt(ecPublicKey.Q!.y!.toBigInteger()!),
      });
  print('--COSE--');
  print(key);
  final cborBytes = key.serialize();
  final Base64Codec base64 = const Base64Codec();
  final bStr = base64.encode(cborBytes);
  print(bStr);
  return 1;
}
