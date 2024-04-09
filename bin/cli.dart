//import 'package:cli/auth_client.dart';
import 'package:authn/authn.dart';

const neededArgsSizeForCloud = 4;

Future<void> main(List<String> args) async {
  if (args.length < neededArgsSizeForCloud - 1 ||
      args.length > neededArgsSizeForCloud) {
    print('Usage: <login/register> <name> <keyID> [op]\n');
    print('       op -> contacts cloud installation');
    return;
  }

  final cmd = args[0];
  final name = args[1];
  final pin = args[2];
  print('cmd: $cmd, name: $name, keyID: $pin');
  if (args.length == neededArgsSizeForCloud) {
    setupFromYAML('cfg-op.yaml');
  } else {
    setupFromYAML('cfg.yaml');
  }
  final jwt = await authnCmd(cmd, name, pin);
  print(jwt);

  return;
}
