import 'package:cli/auth_client.dart';

const neededArgsSize = 3;

Future<void> main(List<String> args) async {
  if (args.length != neededArgsSize) {
    print('Usage: <login/register> <name> <keyID>');
    return;
  }

  final cmd = args[0];
  final name = args[1];
  final pin = args[2];
  print('cmd: $cmd, name: $name, keyID: $pin');

  exec(cmd, name, pin);

  return;
}
