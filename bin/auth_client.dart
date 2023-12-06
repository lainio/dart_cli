import 'dart:convert';

import 'package:grpc/grpc.dart';
import 'package:helloworld/src/generated/authn.pbgrpc.dart';
import 'package:fixnum/fixnum.dart'; // NOTE. for Int64

import 'package:basic_utils/basic_utils.dart';
import 'package:cbor/cbor.dart';
import 'dart:typed_data';

const keyId = 2;

final String curve = 'prime256v1';

class PemPair {
  String? pemPub;
  String? pemPriv;

  AsymmetricKeyPair? pair;

  ECPrivateKey get privateKey => pair!.privateKey as ECPrivateKey;
  ECPublicKey get publicKey => pair!.publicKey as ECPublicKey;

  List<int> get data => utf8.encode('$pemPriv\n$pemPub');

  PemPair.generate() {
    pair = CryptoUtils.generateEcKeyPair(curve: curve);
    pemPriv = CryptoUtils.encodeEcPrivateKeyToPem(privateKey);
    pemPub = CryptoUtils.encodeEcPublicKeyToPem(publicKey);
  }

  PemPair.load(Uint8List d) {
    final strData = utf8.decode(d);
    
    final lines = LineSplitter.split(strData);
    var pemPrivStr = '';
    var pemPubStr = '';
    var pub = false;

    for (var lineStr in lines) {
        if (CryptoUtils.BEGIN_PUBLIC_KEY == lineStr) {
          pub = true;
        }
        if (pub) {
          pemPubStr += '$lineStr\n';
        } else {
          pemPrivStr += '$lineStr\n';
        }
    }
    pemPriv = pemPrivStr;
    pemPub = pemPubStr;
    final privateKey = CryptoUtils.ecPrivateKeyFromPem(pemPrivStr);
    final tmpPubKey = CryptoUtils.ecPublicKeyFromPem(pemPubStr);
    pair = AsymmetricKeyPair(tmpPubKey, privateKey);
  }
}

class Handle {
  Int64 id;
  ECPrivateKey? privateKey;
  List<int>? data;
  ECPublicKey? publicKey;

  Handle.load(Uint8List d) : id = Int64(keyId) {
    final kp = PemPair.load(d);
    privateKey = kp.privateKey;
    publicKey = kp.publicKey;
    data = d;
  }

  Handle() : id = Int64(keyId) {
    final akp = PemPair.generate();

    privateKey = akp.privateKey;
    publicKey = akp.publicKey;
    data = akp.data;
  }

  List<int> toCbor() {
    final ecPublicKey = publicKey!;
    final cborMap = CborMap({
      CborSmallInt(kty): CborSmallInt(2),
      CborSmallInt(alg): CborSmallInt(-7),
      CborSmallInt(crvCOSE): CborSmallInt(1),
      CborSmallInt(xCOSE):
          CborBytes(CborBigInt(ecPublicKey.Q!.x!.toBigInteger()!).bytes),
      CborSmallInt(yCOSE):
          CborBytes(CborBigInt(ecPublicKey.Q!.y!.toBigInteger()!).bytes),
    });
    final cborBytes = cbor.encode(cborMap);
    return cborBytes;
  }

  List<int> sign(List<int> data) {
    final toSign = Uint8List.fromList(data);
    final /*ECSignature*/ sig =
        CryptoUtils.ecSign(privateKey!, toSign, algorithmName: 'SHA-256/ECDSA');
    final b64 = CryptoUtils.ecSignatureToBase64(sig);
    return base64Decode(b64);
  }
}

Handle? myHandle;

Future<void> main(List<String> args) async {
  final channel = ClientChannel(
    'localhost',
    port: 50053,
    options: ChannelOptions(
      credentials: ChannelCredentials.insecure(),
      codecRegistry:
          CodecRegistry(codecs: const [GzipCodec(), IdentityCodec()]),
      //CodecRegistry(codecs: const [GzipCodec()]),
    ),
  );
  final stub = AuthnServiceClient(channel);

  if (args.length != 2) {
    print('Usage: <login/register> <name>');
    return;
  }

  final cmd = args[0];
  final name = args[1];

  final myCMD = cmd == 'login' ? Cmd_Type.LOGIN : Cmd_Type.REGISTER;

  var jwt = '';

  try {
    await for (var cmdStat in stub.enter(
      Cmd(
        type: myCMD, //type: Cmd_Type.REGISTER,
        userName: name,
        uRL: 'http://localhost:8090', // todo: argument/var
        aAGUID: '12c85a48-4baf-47bd-b51f-f192871a1511', // todo: argument/var
      ),
      //options: CallOptions(compression: const GzipCodec()), // this works!!
    )) {
      print('status msg arrives: ${cmdStat.type}');
      switch (cmdStat.type) {
        case CmdStatus_Type.READY_OK:
          jwt = cmdStat.ok.jWT;
          break;
        case CmdStatus_Type.READY_ERR:
          final msg = cmdStat.err;
          print('cmd status ERR, throwing-> "$msg"');
          throw 'Exp: error';
        //break;
        case CmdStatus_Type.STATUS:
          print('==> Has OK: ${cmdStat.type}');
          print('--> received ${cmdStat.secType}');

          switch (cmdStat.secType) {
            case SecretMsg_Type.IS_KEY_HANDLE:
              final myID = Int64(keyId);
              final credID = cmdStat.enclave.credID as Uint8List;
              assert(myHandle == null);
              myHandle = Handle.load(credID);
              assert(myHandle != null);
              stub.enterSecret(SecretMsg(
                  cmdID: cmdStat.cmdID,
                  type: cmdStat.secType,
                  handle: SecretMsg_HandleMsg(iD: myID)));
              break;

            case SecretMsg_Type.CBOR_PUB_KEY:
              final handleID = cmdStat.handle.iD;
              assert(handleID == 2);
              assert(myHandle != null);
              final handle = myHandle!;
              final keyData = handle.toCbor();
              stub.enterSecret(SecretMsg(
                  cmdID: cmdStat.cmdID,
                  type: cmdStat.secType,
                  handle: SecretMsg_HandleMsg(iD: handle.id, data: keyData)));
              break;

            case SecretMsg_Type.NEW_HANDLE:
              final myID = Int64(keyId);
              assert(myHandle == null);
              myHandle = Handle();
              final handle = myHandle!;
              final keyData = handle.data;
              stub.enterSecret(SecretMsg(
                  cmdID: cmdStat.cmdID,
                  type: cmdStat.secType,
                  handle: SecretMsg_HandleMsg(iD: myID, data: keyData)));
              break;

            case SecretMsg_Type.ID:
              final handleID = cmdStat.handle.iD;
              assert(handleID == 2);
              final handle = myHandle!;
              final keyData = handle.data;
              stub.enterSecret(SecretMsg(
                  cmdID: cmdStat.cmdID,
                  type: cmdStat.secType,
                  handle: SecretMsg_HandleMsg(iD: handle.id, data: keyData)));
              break;

            case SecretMsg_Type.SIGN:
              final handleID = cmdStat.handle.iD;
              final toSignData = cmdStat.handle.data;
              assert(handleID == 2);
              final handle = myHandle!;
              final signData = handle.sign(toSignData);
              stub.enterSecret(SecretMsg(
                  cmdID: cmdStat.cmdID,
                  type: cmdStat.secType,
                  handle: SecretMsg_HandleMsg(iD: handle.id, sign: signData)));
              break;

            default:
              print('ERROR: unknown sec type');
          }
          break;
        default:
          print('ERR: type');
      }
    }
  } catch (e) {
    print('Caught error: $e');
  }
  await channel.shutdown();
  print(jwt);
}

const int crvCOSE = -1;
const int xCOSE = -2;
const int yCOSE = -3;

/// Constant for the Key Type.
const int kty = 1;

/// Constant for the Key ID.
const int kid = 2;

/// Constant for the Key Algorithm.
const int alg = 3;
