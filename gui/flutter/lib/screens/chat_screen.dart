import 'package:flutter/material.dart';
import '../theme/enclave_theme.dart';

class ChatScreen extends StatefulWidget {
  final String chatId;
  const ChatScreen({super.key, required this.chatId});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _controller = TextEditingController();
  final _scrollController = ScrollController();

  // placeholder messages — replace with real data
  final List<_Message> _messages = [
    _Message(text: 'hey, is this working?', fromMe: false, time: '9:00 PM'),
    _Message(text: 'yeah! encryption test passed', fromMe: true, time: '9:01 PM'),
    _Message(text: 'nice. commit it', fromMe: false, time: '9:02 PM'),
  ];

  void _send() {
    final text = _controller.text.trim();
    if (text.isEmpty) return;
    setState(() {
      _messages.add(_Message(text: text, fromMe: true, time: 'now'));
      _controller.clear();
    });
    // TODO: send via backend websocket
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeOut,
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('saksham'),
        actions: [
          IconButton(icon: const Icon(Icons.more_vert), onPressed: () {}),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: ListView.builder(
              controller: _scrollController,
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              itemCount: _messages.length,
              itemBuilder: (context, i) => _MessageBubble(message: _messages[i]),
            ),
          ),
          _InputBar(controller: _controller, onSend: _send),
        ],
      ),
    );
  }
}

class _Message {
  final String text, time;
  final bool fromMe;
  const _Message({required this.text, required this.fromMe, required this.time});
}

class _MessageBubble extends StatelessWidget {
  final _Message message;
  const _MessageBubble({super.key, required this.message});

  @override
  Widget build(BuildContext context) {
    final fromMe = message.fromMe;
    return Align(
      alignment: fromMe ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 3),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.75),
        decoration: BoxDecoration(
          color: fromMe ? EnclaveColors.primary : EnclaveColors.surfaceLight,
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(14),
            topRight: const Radius.circular(14),
            bottomLeft: Radius.circular(fromMe ? 14 : 4),
            bottomRight: Radius.circular(fromMe ? 4 : 14),
          ),
          border: fromMe ? null : Border.all(color: EnclaveColors.borderLight),
        ),
        child: Column(
          crossAxisAlignment: fromMe ? CrossAxisAlignment.end : CrossAxisAlignment.start,
          children: [
            Text(
              message.text,
              style: TextStyle(color: fromMe ? Colors.white : EnclaveColors.textLight),
            ),
            const SizedBox(height: 3),
            Text(
              message.time,
              style: TextStyle(
                fontSize: 10,
                color: fromMe ? Colors.white60 : EnclaveColors.faintLight,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _InputBar extends StatelessWidget {
  final TextEditingController controller;
  final VoidCallback onSend;
  const _InputBar({required this.controller, required this.onSend});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 16),
      decoration: const BoxDecoration(
        border: Border(top: BorderSide(color: EnclaveColors.borderLight)),
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: controller,
              minLines: 1,
              maxLines: 5,
              onSubmitted: (_) => onSend(),
              decoration: const InputDecoration(
                hintText: 'message...',
                contentPadding: EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              ),
            ),
          ),
          const SizedBox(width: 8),
          IconButton(
            onPressed: onSend,
            icon: const Icon(Icons.send_rounded),
            color: EnclaveColors.primary,
          ),
        ],
      ),
    );
  }
}
