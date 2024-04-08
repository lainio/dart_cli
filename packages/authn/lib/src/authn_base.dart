import 'command.dart';
import 'auth_client.dart';

class AuthnCommand extends Command {
  AuthnCommand(super.addr, super.port);
}

Future<String> authnCmd(String cmd, name, xorKey) async {
  return exec(cmd, name, xorKey);
}
