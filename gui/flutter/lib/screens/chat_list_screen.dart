import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../theme/enclave_theme.dart';

class ChatListScreen extends StatelessWidget {
  const ChatListScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: RichText(
          text: TextSpan(
            style: Theme.of(context).textTheme.titleLarge,
            children: const [
              TextSpan(text: 'project '),
              TextSpan(
                text: 'enclave',
                style: TextStyle(color: EnclaveColors.coral),
              ),
            ],
          ),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            onPressed: () => context.push('/settings'),
          ),
        ],
      ),
      body: const _ChatList(),
      floatingActionButton: FloatingActionButton(
        backgroundColor: EnclaveColors.primary,
        foregroundColor: Colors.white,
        onPressed: () {
          // TODO: new chat
        },
        child: const Icon(Icons.edit_outlined),
      ),
    );
  }
}

class _ChatList extends StatelessWidget {
  const _ChatList();

  @override
  Widget build(BuildContext context) {
    // placeholder — replace with real data from your backend
    final chats = [
      _ChatPreview(id: '1', name: 'saksham', preview: 'hey did you test the new build?', time: '11:42 PM', unread: 2),
      _ChatPreview(id: '2', name: 'test user', preview: 'encryption is working now', time: '9:15 PM', unread: 0),
    ];

    if (chats.isEmpty) {
      return const _EmptyState();
    }

    return ListView.separated(
      itemCount: chats.length,
      separatorBuilder: (_, __) => const Divider(height: 1),
      itemBuilder: (context, i) => _ChatTile(chat: chats[i]),
    );
  }
}

class _ChatPreview {
  final String id, name, preview, time;
  final int unread;
  const _ChatPreview({required this.id, required this.name, required this.preview, required this.time, required this.unread});
}

class _ChatTile extends StatelessWidget {
  final _ChatPreview chat;
  const _ChatTile({super.key, required this.chat});

  @override
  Widget build(BuildContext context) {
    return ListTile(
      onTap: () => context.push('/chat/${chat.id}'),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      leading: CircleAvatar(
        backgroundColor: EnclaveColors.primary.withOpacity(0.15),
        child: Text(
          chat.name[0].toUpperCase(),
          style: const TextStyle(color: EnclaveColors.primary, fontWeight: FontWeight.bold),
        ),
      ),
      title: Text(chat.name, style: const TextStyle(fontWeight: FontWeight.w600)),
      subtitle: Text(
        chat.preview,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(color: EnclaveColors.mutedLight),
      ),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          Text(chat.time, style: const TextStyle(fontSize: 11, color: EnclaveColors.faintLight)),
          if (chat.unread > 0) ...[
            const SizedBox(height: 4),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: EnclaveColors.primary,
                borderRadius: BorderRadius.circular(99),
              ),
              child: Text(
                '${chat.unread}',
                style: const TextStyle(fontSize: 11, color: Colors.white, fontWeight: FontWeight.bold),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.chat_bubble_outline, size: 48, color: EnclaveColors.faintLight),
          const SizedBox(height: 16),
          const Text('no conversations yet', style: TextStyle(color: EnclaveColors.mutedLight)),
          const SizedBox(height: 8),
          const Text('tap + to start one', style: TextStyle(fontSize: 12, color: EnclaveColors.faintLight)),
        ],
      ),
    );
  }
}
