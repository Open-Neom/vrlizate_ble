import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Event categories emitted by a native BLE GATT duplex peripheral server.
enum VrBleGattEventType {
  started,
  stopped,
  clientConnected,
  clientDisconnected,
  duplexData,
  duplexClientSubscribed,
  duplexClientUnsubscribed,
  duplexMtuChanged,
  advertisingStarted,
  advertisingFailed,
  other,
  error,
}

/// Parsed native BLE GATT server event delivered to [VrBleHost].
class VrBleGattEvent {
  final VrBleGattEventType type;
  final String? deviceId;
  final int offset;
  final int length;
  final String? message;
  final Uint8List? data;
  final int? mtu;
  final int? maxNotificationBytes;

  const VrBleGattEvent({
    required this.type,
    this.deviceId,
    this.offset = 0,
    this.length = 0,
    this.message,
    this.data,
    this.mtu,
    this.maxNotificationBytes,
  });

  factory VrBleGattEvent.fromMap(Map<dynamic, dynamic> map) {
    final rawType = map['type'] as String? ?? '';
    final type = switch (rawType) {
      'started' => VrBleGattEventType.started,
      'stopped' => VrBleGattEventType.stopped,
      'clientConnected' => VrBleGattEventType.clientConnected,
      'clientDisconnected' => VrBleGattEventType.clientDisconnected,
      'duplexData' => VrBleGattEventType.duplexData,
      'duplexClientSubscribed' => VrBleGattEventType.duplexClientSubscribed,
      'duplexClientUnsubscribed' => VrBleGattEventType.duplexClientUnsubscribed,
      'duplexMtuChanged' => VrBleGattEventType.duplexMtuChanged,
      'advertisingStarted' => VrBleGattEventType.advertisingStarted,
      'advertisingFailed' => VrBleGattEventType.advertisingFailed,
      'chunkServed' ||
      'beaconClientSubscribed' ||
      'beaconClientUnsubscribed' ||
      'beaconData' => VrBleGattEventType.other,
      _ => VrBleGattEventType.error,
    };
    return VrBleGattEvent(
      type: type,
      deviceId: map['deviceId'] as String?,
      offset: (map['offset'] as num?)?.toInt() ?? 0,
      length: (map['length'] as num?)?.toInt() ?? 0,
      message: map['message'] as String?,
      data: map['data'] is Uint8List ? map['data'] as Uint8List : null,
      mtu: (map['mtu'] as num?)?.toInt(),
      maxNotificationBytes: (map['maxNotificationBytes'] as num?)?.toInt(),
    );
  }
}

/// Thrown when [VrBleHost] cannot host a BLE GATT peripheral service because
/// no peripheral backend is linked in the host application
/// ([isBackendMissing] == `true`) or the current device/platform does not
/// support BLE peripheral/GATT server mode.
class VrBlePeripheralUnsupportedException implements Exception {
  const VrBlePeripheralUnsupportedException(
    this.message, {
    this.isBackendMissing = false,
  });

  final String message;

  /// `true` when the default native channel (`dev.neom.ble/gatt_server`) had
  /// no plugin handler registered ([MissingPluginException]), distinguishing a
  /// host integration omission from hardware/OS peripheral incompatibility.
  final bool isBackendMissing;

  @override
  String toString() => message;
}

/// Pluggable BLE GATT peripheral interface used by [VrBleHost] on the Visor.
///
/// By default, [createDefault] returns [MethodChannelVrBleGattPeripheral],
/// which communicates directly with the native GATT peripheral channels
/// (`dev.neom.ble/gatt_server` and `dev.neom.ble/gatt_server_events`) provided
/// when `neom_ble` (or a compatible peripheral plugin) is linked in the host
/// application — without requiring a public `pubspec.yaml` dependency on private
/// packages. Host integrations such as `neom_vr` can also register a typed
/// wrapper via [defaultFactory] or pass `gatt:` explicitly to `VrBleHost`.
abstract interface class VrBleGattPeripheralAdapter {
  static const int maxDuplexFragmentBytes = 512;

  /// Optional host-registered factory (e.g. `NeomBleGattPeripheralAdapter` in
  /// `neom_vr`). Falls back to [MethodChannelVrBleGattPeripheral] when unset.
  static VrBleGattPeripheralAdapter Function()? defaultFactory;

  static VrBleGattPeripheralAdapter createDefault() =>
      defaultFactory?.call() ?? MethodChannelVrBleGattPeripheral();

  Stream<VrBleGattEvent> get events;

  Future<bool> isSupported();

  Future<bool> startDuplexService({
    required String serviceUuid,
    required String rxCharUuid,
    required String txCharUuid,
  });

  Future<void> stopDuplexService();

  Future<bool> notifyDuplex({
    required String deviceId,
    required Uint8List data,
  });

  Future<bool> disconnectDuplexClient({required String deviceId});

  Future<bool> startConnectableAdvertising({required String serviceUuid});

  Future<void> stopAdvertising();
}

/// Default [MethodChannel] / [EventChannel] peripheral implementation compatible
/// with the native Android/iOS/macOS `NeomDuplexGattService` channel contract.
class MethodChannelVrBleGattPeripheral implements VrBleGattPeripheralAdapter {
  MethodChannelVrBleGattPeripheral({
    MethodChannel methodChannel = const MethodChannel(
      'dev.neom.ble/gatt_server',
    ),
    EventChannel eventChannel = const EventChannel(
      'dev.neom.ble/gatt_server_events',
    ),
    bool? overrideNativePlatform,
  }) : _methodChannel = methodChannel,
       _eventChannel = eventChannel,
       _overrideNativePlatform = overrideNativePlatform;

  final MethodChannel _methodChannel;
  final EventChannel _eventChannel;
  final bool? _overrideNativePlatform;
  bool? _supportedCache;
  bool _backendMissing = false;
  Stream<VrBleGattEvent>? _instanceEvents;

  /// After [isSupported] resolves, indicates whether a native channel handler
  /// was registered (`true`) or threw [MissingPluginException] (`false`).
  /// Returns `null` before [isSupported] has been queried or on non-native
  /// targets where the channel is never invoked.
  bool? get isBackendRegistered =>
      (_supportedCache == null || !_isNativePlatform) ? null : !_backendMissing;

  static final Map<String, Stream<VrBleGattEvent>> _sharedEventStreams =
      <String, Stream<VrBleGattEvent>>{};

  static final RegExp _uuidPattern = RegExp(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
  );

  bool get _isNativePlatform =>
      _overrideNativePlatform ??
      (!kIsWeb &&
          (defaultTargetPlatform == TargetPlatform.android ||
              defaultTargetPlatform == TargetPlatform.iOS ||
              defaultTargetPlatform == TargetPlatform.macOS));

  @override
  Future<bool> isSupported() async {
    if (!_isNativePlatform) {
      _supportedCache = false;
      return false;
    }
    final cached = _supportedCache;
    if (cached != null) return cached;
    try {
      final result = await _methodChannel.invokeMethod<bool>(
        'isGattServerSupported',
      );
      _backendMissing = false;
      _supportedCache = result ?? false;
    } on MissingPluginException {
      _backendMissing = true;
      _supportedCache = false;
    } catch (_) {
      _supportedCache = false;
    }
    return _supportedCache!;
  }

  @override
  Future<bool> startDuplexService({
    required String serviceUuid,
    required String rxCharUuid,
    required String txCharUuid,
  }) async {
    final uuids = [serviceUuid, rxCharUuid, txCharUuid];
    if (uuids.any((uuid) => uuid.length != 36 || !_uuidPattern.hasMatch(uuid)) ||
        uuids.map((uuid) => uuid.toLowerCase()).toSet().length != 3) {
      throw ArgumentError(
        'Duplex service/RX/TX must be distinct 128-bit UUIDs',
      );
    }
    if (!await isSupported()) return false;
    return await _methodChannel.invokeMethod<bool>('startDuplexService', {
          'serviceUuid': serviceUuid,
          'rxCharUuid': rxCharUuid,
          'txCharUuid': txCharUuid,
        }) ??
        false;
  }

  @override
  Future<void> stopDuplexService() async {
    if (!await isSupported()) return;
    await _methodChannel.invokeMethod<void>('stopDuplexService');
  }

  @override
  Future<bool> notifyDuplex({
    required String deviceId,
    required Uint8List data,
  }) async {
    if (deviceId.isEmpty) throw ArgumentError.value(deviceId, 'deviceId');
    if (data.isEmpty ||
        data.length > VrBleGattPeripheralAdapter.maxDuplexFragmentBytes) {
      throw ArgumentError.value(
        data.length,
        'data.length',
        'Expected 1–${VrBleGattPeripheralAdapter.maxDuplexFragmentBytes}',
      );
    }
    if (!await isSupported()) return false;
    return await _methodChannel.invokeMethod<bool>('notifyDuplex', {
          'deviceId': deviceId,
          'data': data,
        }) ??
        false;
  }

  @override
  Future<bool> disconnectDuplexClient({required String deviceId}) async {
    if (deviceId.isEmpty) throw ArgumentError.value(deviceId, 'deviceId');
    if (!await isSupported()) return false;
    return await _methodChannel.invokeMethod<bool>('disconnectDuplexClient', {
          'deviceId': deviceId,
        }) ??
        false;
  }

  @override
  Future<bool> startConnectableAdvertising({
    required String serviceUuid,
  }) async {
    if (!await isSupported()) return false;
    final result = await _methodChannel.invokeMethod<bool>(
      'startConnectableAdvertising',
      <String, dynamic>{'serviceUuid': serviceUuid},
    );
    return result ?? false;
  }

  @override
  Future<void> stopAdvertising() async {
    if (!await isSupported()) return;
    await _methodChannel.invokeMethod<void>('stopAdvertising');
  }

  Stream<VrBleGattEvent> _nativeBroadcastStream() =>
      _sharedEventStreams.putIfAbsent(
        _eventChannel.name,
        () => _eventChannel.receiveBroadcastStream().map(
          (dynamic event) => VrBleGattEvent.fromMap(event as Map),
        ),
      );

  @override
  Stream<VrBleGattEvent> get events {
    if (!_isNativePlatform || _supportedCache == false) {
      return const Stream<VrBleGattEvent>.empty();
    }
    if (_supportedCache == true) {
      return _instanceEvents ??= _nativeBroadcastStream();
    }
    return _instanceEvents ??= _createGatedEventStream();
  }

  Stream<VrBleGattEvent> _createGatedEventStream() {
    StreamSubscription<VrBleGattEvent>? upstream;
    late final StreamController<VrBleGattEvent> controller;
    var generation = 0;
    controller = StreamController<VrBleGattEvent>.broadcast(
      sync: true,
      onListen: () {
        final activeGen = ++generation;
        unawaited(() async {
          if (!await isSupported()) return;
          if (activeGen != generation || !controller.hasListener) return;
          upstream = _nativeBroadcastStream().listen(
            controller.add,
            onError: controller.addError,
            onDone: () {
              upstream = null;
            },
          );
        }());
      },
      onCancel: () async {
        generation++;
        final sub = upstream;
        upstream = null;
        await sub?.cancel();
      },
    );
    return controller.stream;
  }
}
