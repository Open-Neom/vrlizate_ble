import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:vrlizate/vrlizate.dart' show VrDirectDeviceBridge;

/// Resolves compact local device capability summaries for `vrlizate_ble`
/// 5 GHz hybrid link negotiation (`VrHybridBleUdpHostLink` /
/// `VrHybridBleUdpClientLink`) without coupling `vrlizate_ble` to 3D GPU
/// scene packages.
abstract final class VrBlePeerCapabilities {
  static const MethodChannel _channel = MethodChannel(
    'vrlizate/device_capabilities',
  );

  /// Optional host-registered callback (registered automatically by
  /// `VrDeviceProfiler` in `vrlizate_tracking` when loaded).
  static Future<Map<String, Object?>?> Function()? readPeerSummary;

  static Future<Map<String, Object?>?> resolve() async {
    final custom = readPeerSummary;
    if (custom != null) {
      try {
        return await custom();
      } catch (_) {}
    }
    if (kIsWeb) return null;
    final directBridge = VrDirectDeviceBridge.instance;
    final supportsDirect = switch (defaultTargetPlatform) {
      TargetPlatform.android => directBridge.androidOpenXrHandlesSync() != null,
      TargetPlatform.iOS || TargetPlatform.macOS => directBridge.isAvailable,
      _ => false,
    };
    if (!supportsDirect && defaultTargetPlatform != TargetPlatform.android) {
      return null;
    }
    try {
      Object? raw;
      if (supportsDirect) {
        raw = directBridge.readDeviceCapabilitiesSync();
      }
      if (raw == null && defaultTargetPlatform == TargetPlatform.android) {
        raw = await _channel
            .invokeMethod<Object?>('read')
            .timeout(const Duration(milliseconds: 900));
      }
      if (raw is! Map) return null;
      final maker = (raw['manufacturer'] as String?)?.trim() ?? '';
      final model = (raw['model'] as String?)?.trim() ?? '';
      if (maker.isEmpty && model.isEmpty) return null;
      final ramMb = (raw['totalRamMb'] as num?)?.toInt();
      final mpc = (raw['mediaPerformanceClass'] as num?)?.toInt();
      final gyro = raw['hasHardwareGyroscope'] as bool?;
      final haptics = raw['hasLinearHaptics'] as bool?;
      final cam3 = raw['hasConcurrentCameras'] as bool?;
      final wifi5 = raw['supportsWifi5Ghz'] as bool?;
      final staAp = raw['supportsStaApConcurrency'] as bool?;
      final wifiOn = raw['wifiConnected'] as bool?;
      final freqMhz = (raw['wifiFrequencyMhz'] as num?)?.toInt();
      final audio = raw['audioOutputKind'] as String?;

      double maxHz = 60.0;
      final modes = raw['supportedModes'];
      if (modes is List) {
        for (final m in modes) {
          if (m is Map) {
            final hz = (m['refreshRateHz'] as num?)?.toDouble();
            if (hz != null && hz > maxHz) maxHz = hz;
          }
        }
      }
      final cls = _inferDeviceClass(
        model: model,
        ramMb: ramMb,
        mpc: mpc,
        maxHz: maxHz,
      );
      return <String, Object?>{
        'maker': maker,
        'model': model,
        'cls': cls,
        if (ramMb != null) 'ramMb': ramMb,
        if (mpc != null && mpc > 0) 'mpc': mpc,
        if (gyro != null) 'gyro': gyro,
        if (haptics != null) 'haptics': haptics,
        if (cam3 != null) 'cam3': cam3,
        if (wifi5 != null) 'wifi5': wifi5,
        if (staAp != null) 'staAp': staAp,
        if (wifiOn != null) 'wifiOn': wifiOn,
        if (freqMhz != null) 'freqMhz': freqMhz,
        if (audio != null) 'audio': audio,
        'maxHz': maxHz.round(),
      };
    } catch (_) {
      return null;
    }
  }

  static String _inferDeviceClass({
    required String model,
    required int? ramMb,
    required int? mpc,
    required double maxHz,
  }) {
    final upper = model.toUpperCase();
    if (upper.startsWith('SM-S9') ||
        upper.contains('ULTRA') ||
        upper.contains('PIXEL 8 PRO') ||
        upper.contains('PIXEL 9') ||
        (mpc != null && mpc >= 34) ||
        (ramMb != null && ramMb >= 10500 && maxHz >= 115)) {
      return 'flagship';
    }
    if ((ramMb != null && ramMb < 4500) || upper.startsWith('SM-A0')) {
      return 'entry';
    }
    return 'mid';
  }
}
