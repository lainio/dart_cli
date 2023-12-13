import 'package:cli/auth_client.dart';

Future<void> main(List<String> args) async {
  if (args.length != 2) {
    print('Usage: <login/register> <name>');
    return;
  }

  final cmd = args[0];
  final name = args[1];
  print('cmd: $cmd, name: $name');

  exec(cmd, name);

  return;
}
