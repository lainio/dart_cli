import 'package:cryptography/cryptography.dart';
import 'package:dart_wot/dart_wot.dart';

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

  final coseKey = CoseKey(keyType: KeyType.ec2, keyId: [1, 2, 3], algorithm: Algorithm.es256);
  print(coseKey.toString());
  final cosePubKey = PlainCoseKey(coseKey);
  final pkStr = cosePubKey.toString();
  print(pkStr);
  
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

Future<void> main3() async {
  // In this example, we use ECDSA-P256-SHA256
  final algorithm = Ecdsa.p256(Sha256());

  print(algorithm.keyPairType);
  // Generate a random key pair
  final secretKey = await algorithm.newKeyPair();
  //final secretKey = await algorithm.newSecretKey();
  //final publicKey = await algorithm.publicKey(secretKey);

  // Sign a message
  final message = <int>[1,2,3];
  final signature = await algorithm.sign(
    [1,2,3],
    keyPair: secretKey,
  );

  // Anyone can verify the signature
  final isVerified = await algorithm.verify(
    message,
    signature: signature,
  );
  print('signature: $isVerified');
}
