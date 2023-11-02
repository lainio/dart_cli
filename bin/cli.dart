import 'package:cryptography/cryptography.dart';
//import 'package:dart_wot/dart_wot.dart';

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

import 'package:basic_utils/basic_utils.dart';

Future<void> main3() async {
  // the private key
  ECPrivateKey? privateKey;
  
  final akp = CryptoUtils.generateEcKeyPair();
  final pubKey = akp.publicKey as ECPublicKey;
  final x = pubKey.Q!.x;
  print(x);
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
  final encoded = ASN1Sequence(elements: [
    ASN1Integer(ecSignature.r),
    ASN1Integer(ecSignature.s),
  ]).encode();

  // and finally base 64 encode it
  final signature = base64UrlEncode(encoded);
  print(signature);

  ECSignature sig = CryptoUtils.ecSign(privateKey, bytes, algorithmName: 'SHA-256/ECDSA');
  final signature2 = CryptoUtils.ecSignatureToBase64(sig);
  print(signature2);
}

Future<void> main() async {
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
  
  print('=============');
  await main3();
}

Future<void> main2() async {
  final algorithm = Ed25519();

  // Generate a key pair
  final keyPair = await algorithm.newKeyPair();
  final e = await keyPair.extractPrivateKeyBytes();
  print('privatekeybytes');
  print(e.toString());

  // Sign a message
  final message = <int>[1,2,3];
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

