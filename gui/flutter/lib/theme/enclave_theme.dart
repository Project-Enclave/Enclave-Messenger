import 'package:flutter/material.dart';

/// Enclave design tokens — mirrors the CSS variables in the website.
class EnclaveColors {
  // light
  static const bgLight      = Color(0xFFFDF5F0);
  static const surfaceLight = Color(0xFFFEF8F4);
  static const borderLight  = Color(0xFFF0CFC4);
  static const textLight    = Color(0xFF2A1F2E);
  static const mutedLight   = Color(0xFF6B4F5E);
  static const faintLight   = Color(0xFFC4A5B0);

  // dark
  static const bgDark      = Color(0xFF1A1218);
  static const surfaceDark = Color(0xFF221620);
  static const borderDark  = Color(0xFF4A3348);
  static const textDark    = Color(0xFFF5DDE5);
  static const mutedDark   = Color(0xFFD4A8BA);
  static const faintDark   = Color(0xFF8A6678);

  // accent (same in both modes)
  static const primary = Color(0xFFC16C86);
  static const coral   = Color(0xFFF27280);
  static const warm    = Color(0xFFF9B294);
  static const purple  = Color(0xFF6D5C7D);
}

class EnclaveTheme {
  static ThemeData light() {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.light,
      scaffoldBackgroundColor: EnclaveColors.bgLight,
      colorScheme: ColorScheme.light(
        primary: EnclaveColors.primary,
        secondary: EnclaveColors.coral,
        tertiary: EnclaveColors.purple,
        surface: EnclaveColors.surfaceLight,
        onPrimary: Colors.white,
        onSurface: EnclaveColors.textLight,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: EnclaveColors.surfaceLight,
        foregroundColor: EnclaveColors.textLight,
        elevation: 0,
        scrolledUnderElevation: 1,
      ),
      cardTheme: CardThemeData(
        color: EnclaveColors.surfaceLight,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
          side: const BorderSide(color: EnclaveColors.borderLight),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: EnclaveColors.surfaceLight,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: EnclaveColors.borderLight),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: EnclaveColors.borderLight),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: EnclaveColors.primary, width: 1.5),
        ),
      ),
      textTheme: const TextTheme(
        bodyMedium: TextStyle(color: EnclaveColors.mutedLight),
        bodyLarge: TextStyle(color: EnclaveColors.textLight),
        labelSmall: TextStyle(color: EnclaveColors.faintLight),
      ),
      dividerTheme: const DividerThemeData(
        color: EnclaveColors.borderLight,
        thickness: 1,
      ),
    );
  }

  static ThemeData dark() {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: EnclaveColors.bgDark,
      colorScheme: ColorScheme.dark(
        primary: EnclaveColors.coral,
        secondary: EnclaveColors.warm,
        tertiary: EnclaveColors.primary,
        surface: EnclaveColors.surfaceDark,
        onPrimary: Colors.white,
        onSurface: EnclaveColors.textDark,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: EnclaveColors.surfaceDark,
        foregroundColor: EnclaveColors.textDark,
        elevation: 0,
        scrolledUnderElevation: 1,
      ),
      cardTheme: CardThemeData(
        color: EnclaveColors.surfaceDark,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
          side: const BorderSide(color: EnclaveColors.borderDark),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: EnclaveColors.surfaceDark,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: EnclaveColors.borderDark),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: EnclaveColors.borderDark),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: EnclaveColors.coral, width: 1.5),
        ),
      ),
      textTheme: const TextTheme(
        bodyMedium: TextStyle(color: EnclaveColors.mutedDark),
        bodyLarge: TextStyle(color: EnclaveColors.textDark),
        labelSmall: TextStyle(color: EnclaveColors.faintDark),
      ),
      dividerTheme: const DividerThemeData(
        color: EnclaveColors.borderDark,
        thickness: 1,
      ),
    );
  }
}
