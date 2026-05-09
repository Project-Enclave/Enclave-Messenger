import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import 'theme/enclave_theme.dart';
import 'screens/chat_list_screen.dart';
import 'screens/chat_screen.dart';
import 'screens/settings_screen.dart';

void main() {
  runApp(const ProviderScope(child: EnclaveApp()));
}

final _router = GoRouter(
  initialLocation: '/',
  routes: [
    GoRoute(
      path: '/',
      builder: (context, state) => const ChatListScreen(),
    ),
    GoRoute(
      path: '/chat/:id',
      builder: (context, state) => ChatScreen(chatId: state.pathParameters['id']!),
    ),
    GoRoute(
      path: '/settings',
      builder: (context, state) => const SettingsScreen(),
    ),
  ],
);

class EnclaveApp extends ConsumerWidget {
  const EnclaveApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return MaterialApp.router(
      title: 'Enclave Messenger',
      debugShowCheckedModeBanner: false,
      theme: EnclaveTheme.light(),
      darkTheme: EnclaveTheme.dark(),
      themeMode: ThemeMode.system,
      routerConfig: _router,
    );
  }
}
