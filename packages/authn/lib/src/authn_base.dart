import 'auth_client.dart';

Future<String> authnCmd(String cmd, name, xorKey) async {
  return exec(cmd, name, xorKey);
}
