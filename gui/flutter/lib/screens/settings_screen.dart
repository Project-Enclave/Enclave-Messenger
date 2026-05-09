import 'package:flutter/material.dart';
import '../theme/enclave_theme.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('settings')),
      body: ListView(
        children: [
          _SectionHeader('account'),
          _SettingsTile(icon: Icons.person_outline, label: 'identity', subtitle: 'view your enclave ID'),
          _SettingsTile(icon: Icons.key_outlined, label: 'encryption keys', subtitle: 'manage your key pair'),
          const Divider(),
          _SectionHeader('appearance'),
          _SettingsTile(icon: Icons.palette_outlined, label: 'theme', subtitle: 'enclave default'),
          _SettingsTile(icon: Icons.view_quilt_outlined, label: 'layout', subtitle: 'enclave default — more coming soon'),
          const Divider(),
          _SectionHeader('network'),
          _SettingsTile(icon: Icons.dns_outlined, label: 'server', subtitle: 'configure backend host'),
          _SettingsTile(icon: Icons.sms_outlined, label: 'sms gateway', subtitle: 'fallback when internet is down'),
          const Divider(),
          _SectionHeader('about'),
          _SettingsTile(icon: Icons.info_outline, label: 'version', subtitle: '0.1.0 — very very early alpha'),
          _SettingsTile(icon: Icons.open_in_new, label: 'project enclave', subtitle: 'projectenclave.dev'),
        ],
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  final String label;
  const _SectionHeader(this.label);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 4),
      child: Text(
        label,
        style: const TextStyle(
          fontSize: 11,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.08,
          color: EnclaveColors.faintLight,
        ),
      ),
    );
  }
}

class _SettingsTile extends StatelessWidget {
  final IconData icon;
  final String label, subtitle;
  const _SettingsTile({required this.icon, required this.label, required this.subtitle});

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Icon(icon, color: EnclaveColors.mutedLight, size: 20),
      title: Text(label),
      subtitle: Text(subtitle, style: const TextStyle(fontSize: 12, color: EnclaveColors.faintLight)),
      trailing: const Icon(Icons.chevron_right, color: EnclaveColors.faintLight, size: 18),
      onTap: () {},
    );
  }
}
