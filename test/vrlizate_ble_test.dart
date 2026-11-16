import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vrlizate/vrlizate.dart' show VrCompactGamepadFrame;
import 'package:vrlizate_ble/vrlizate_ble.dart';
import 'package:vrlizate_joystick/vrlizate_joystick.dart';

class _FakeGattPeripheral implements VrBleGattPeripheralAdapter {
  _FakeGattPeripheral({this.supported = true}) {
    _resetController();
  }

  bool supported;
  late StreamController<VrBleGattEvent> incoming;
  int listenCount = 0;
  Completer<bool>? pendingStart;
  final calls = <String>[];
  bool published = false;
  bool advertising = false;

  void _resetController() {
    incoming = StreamController<VrBleGattEvent>.broadcast(
      sync: true,
      onListen: () => listenCount++,
    );
  }

  Future<void> closeAndReplaceStream() async {
    final prev = incoming;
    _resetController();
    await prev.close();
  }

  @override
  Stream<VrBleGattEvent> get events => incoming.stream;

  @override
  Future<bool> isSupported() async => supported;

  @override
  Future<bool> startDuplexService({
    required String serviceUuid,
    required String rxCharUuid,
    required String txCharUuid,
  }) async {
    calls.add('start:$serviceUuid');
    final pending = pendingStart;
    pendingStart = null;
    final ok = pending != null ? await pending.future : true;
    published = ok;
    return ok;
  }

  @override
  Future<void> stopDuplexService() async {
    calls.add('stop-service');
    published = false;
  }

  @override
  Future<bool> notifyDuplex({
    required String deviceId,
    required Uint8List data,
  }) async => true;

  @override
  Future<bool> disconnectDuplexClient({required String deviceId}) async => true;

  @override
  Future<bool> startConnectableAdvertising({
    required String serviceUuid,
  }) async {
    calls.add('advertise:$serviceUuid');
    advertising = true;
    return true;
  }

  @override
  Future<void> stopAdvertising() async {
    calls.add('stop-advertise');
    advertising = false;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('VrBleWireCodec encodes and decodes 21-byte state packet losslessly', () {
    final original = jsonEncode({
      'sequence': 42,
      'hostModeRevision': 7,
      'mode': 'driving',
      'stickX': 0.5,
      'stickY': -0.5,
      'btnA': true,
      'btnB': false,
      'trigger': true,
      'throttle': 0.8,
      'brake': 0.0,
    });
    final encoded = VrBleWireCodec.encode(original);
    expect(encoded.length, VrBleWireCodec.statePacketBytes);
    final decoded = jsonDecode(VrBleWireCodec.decode(encoded)) as Map<String, dynamic>;
    expect(decoded['sequence'], 42);
    expect(decoded['hostModeRevision'], 7);
    expect(decoded['mode'], 'driving');
    expect(decoded['btnA'], isTrue);
    expect(decoded['trigger'], isTrue);
    expect((decoded['stickX'] as num).toDouble(), closeTo(0.5, 0.02));
  });

  test('MethodChannelVrBleGattPeripheral routes duplex calls over channel', () async {
    const channel = MethodChannel('test.vrlizate.ble/gatt_server');
    final log = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          log.add(call);
          return true;
        });
    addTearDown(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
    });

    final adapter = MethodChannelVrBleGattPeripheral(
      methodChannel: channel,
      overrideNativePlatform: true,
    );
    final svcUuid = newVrBleServiceUuid();
    expect(await adapter.isSupported(), isTrue);
    expect(
      await adapter.startDuplexService(
        serviceUuid: svcUuid,
        rxCharUuid: vrBleRxUuid,
        txCharUuid: vrBleTxUuid,
      ),
      isTrue,
    );
    expect(
      await adapter.notifyDuplex(
        deviceId: 'peer-1',
        data: Uint8List.fromList([1, 2, 3]),
      ),
      isTrue,
    );
    expect(log.map((c) => c.method), [
      'isGattServerSupported',
      'startDuplexService',
      'notifyDuplex',
    ]);
  });

  test('VrBleHost republishes service after Bluetooth adapter recovery', () async {
    final gatt = _FakeGattPeripheral();
    final adapter = StreamController<BluetoothAdapterState>.broadcast(sync: true);
    final controller = VrRemoteControllerService();
    final host = VrBleHost(
      controller,
      gatt: gatt,
      adapterStates: adapter.stream,
      prepareBluetooth: () async {},
    );
    addTearDown(() async {
      await host.dispose();
      controller.dispose();
      await adapter.close();
      await gatt.incoming.close();
    });

    final invitation = await host.start();
    expect(gatt.published, isTrue);
    expect(gatt.advertising, isTrue);

    adapter.add(BluetoothAdapterState.off);
    for (var i = 0; i < 12; i++) {
      await Future<void>.delayed(Duration.zero);
    }
    expect(gatt.published, isFalse);

    adapter.add(BluetoothAdapterState.on);
    for (var i = 0; i < 12; i++) {
      await Future<void>.delayed(Duration.zero);
    }
    expect(gatt.published, isTrue);
    expect(gatt.advertising, isTrue);
    expect(host.invitation.bleServiceUuid, invitation.bleServiceUuid);
  });

  test('VrHybridBleUdpHostLink and ClientLink upgrade to 5 GHz UDP on loopback', () async {
    const token = 'hybrid-ble-udp-unit-test-secret-token';
    late VrBlePacketLink hostBle;
    late VrBlePacketLink clientBle;

    hostBle = VrBlePacketLink(
      writeChunk: (chunk) async => clientBle.receive(chunk),
      onClose: () async {},
    )..enableSinglePacketState();
    clientBle = VrBlePacketLink(
      writeChunk: (chunk) async => hostBle.receive(chunk),
      onClose: () async {},
    )..enableSinglePacketState();

    final service = VrRemoteControllerService(sessionToken: token);
    VrHybridBleUdpHostLink? hybridHost;

    VrBleHostPeer(
      link: hostBle,
      sessionToken: token,
      onAuthenticated: (authenticatedBle) {
        hybridHost = VrHybridBleUdpHostLink(
          bleLink: authenticatedBle,
          sessionToken: token,
          overrideLanIps: const ['127.0.0.1'],
          bindAddress: InternetAddress.loopbackIPv4,
          localCapabilitiesSummary: const {
            'maker': 'Samsung',
            'model': 'SM-S938B',
            'cls': 'flagship',
            'wifiOn': true,
            'wifi5': true,
            'freqMhz': 5180,
            'maxHz': 120,
          },
        );
        return service.attachControllerLink(hybridHost!, sessionToken: token);
      },
    );

    final clientPeer = VrBleClientPeer(link: clientBle, sessionToken: token);
    final readyBle = await clientPeer.ready;
    final hybridClient = VrHybridBleUdpClientLink(
      bleLink: readyBle,
      sessionToken: token,
      bindAddress: InternetAddress.loopbackIPv4,
      localCapabilitiesSummary: const {
        'maker': 'Samsung',
        'model': 'SM-S931B',
        'cls': 'flagship',
        'wifiOn': true,
        'wifi5': true,
        'freqMhz': 5180,
        'maxHz': 120,
        'gyro': true,
      },
    );
    final sub = hybridClient.messages.listen((_) {});
    for (var i = 0; i < 30 && !hybridClient.isUdpActive; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    expect(hybridClient.isUdpActive, isTrue);
    expect(
      hybridClient.linkQualityListenable.value.recommendedHz,
      120,
    );

    hybridClient.add(jsonEncode({'sequence': 1, 'stickX': -0.5, 'btnA': true}));
    await Future<void>.delayed(const Duration(milliseconds: 25));
    expect(service.latestState.btnA, isTrue);
    expect(service.latestState.stickX, closeTo(-0.5, 0.02));

    await sub.cancel();
    await hybridClient.close();
    await hybridHost!.close();
    service.dispose();
  });

  test(
    'VrBleHost without registered GATT backend throws VrBlePeripheralUnsupportedException without opening EventChannel or preparing permissions',
    () async {
      const methodChannel = MethodChannel('test.vrlizate.ble/missing_gatt');
      const eventChannel = EventChannel(
        'test.vrlizate.ble/missing_gatt_events',
      );
      const eventCodecChannel = MethodChannel(
        'test.vrlizate.ble/missing_gatt_events',
      );
      var eventListenCalls = 0;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(eventCodecChannel, (call) async {
            if (call.method == 'listen') eventListenCalls++;
            return null;
          });
      addTearDown(() {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(eventCodecChannel, null);
      });

      final adapter = MethodChannelVrBleGattPeripheral(
        methodChannel: methodChannel,
        eventChannel: eventChannel,
        overrideNativePlatform: true,
      );
      final controller = VrRemoteControllerService();
      var prepareCalls = 0;
      final host = VrBleHost(
        controller,
        gatt: adapter,
        prepareBluetooth: () async => prepareCalls++,
      );
      addTearDown(() async {
        await host.dispose();
        controller.dispose();
      });

      await expectLater(
        host.start(),
        throwsA(
          isA<VrBlePeripheralUnsupportedException>()
              .having((e) => e.isBackendMissing, 'isBackendMissing', isTrue)
              .having(
                (e) => e.message,
                'message',
                contains('dev.neom.ble/gatt_server'),
              ),
        ),
      );
      expect(adapter.isBackendRegistered, isFalse);
      expect(prepareCalls, 0);
      expect(eventListenCalls, 0);
    },
  );

  test(
    'VrBleHost distinguishes hardware isSupported == false from denied Bluetooth permissions',
    () async {
      const unsupportedChannel = MethodChannel(
        'test.vrlizate.ble/unsupported_hw',
      );
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(unsupportedChannel, (call) async {
            if (call.method == 'isGattServerSupported') return false;
            return false;
          });
      addTearDown(() {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(unsupportedChannel, null);
      });

      final unsupportedAdapter = MethodChannelVrBleGattPeripheral(
        methodChannel: unsupportedChannel,
        eventChannel: const EventChannel(
          'test.vrlizate.ble/unsupported_hw_events',
        ),
        overrideNativePlatform: true,
      );
      final controller = VrRemoteControllerService();
      final unsupportedHost = VrBleHost(
        controller,
        gatt: unsupportedAdapter,
        prepareBluetooth: () async =>
            throw StateError('Should not prepare permissions when unsupported'),
      );

      await expectLater(
        unsupportedHost.start(),
        throwsA(
          isA<VrBlePeripheralUnsupportedException>()
              .having((e) => e.isBackendMissing, 'isBackendMissing', isFalse)
              .having(
                (e) => e.message,
                'message',
                contains('modo periférico BLE GATT'),
              ),
        ),
      );
      expect(unsupportedAdapter.isBackendRegistered, isTrue);
      await unsupportedHost.dispose();

      // Now verify supported peripheral + denied permissions surfaces StateError,
      // not VrBlePeripheralUnsupportedException.
      final supportedGatt = _FakeGattPeripheral();
      final permissionDeniedHost = VrBleHost(
        controller,
        gatt: supportedGatt,
        prepareBluetooth: () async =>
            throw StateError('Permisos Bluetooth denegados por el usuario.'),
      );
      addTearDown(() async {
        await permissionDeniedHost.dispose();
        await supportedGatt.incoming.close();
        controller.dispose();
      });

      await expectLater(
        permissionDeniedHost.start(),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Permisos Bluetooth denegados'),
          ),
        ),
      );
      expect(supportedGatt.published, isFalse);
    },
  );

  testWidgets(
    'VrDevicePairingPage displays peripheral backend contract message instead of permissions hint when GATT backend is missing',
    (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(1080, 600);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.view.resetPhysicalSize);

      final service = VrRemoteControllerService();
      addTearDown(service.dispose);

      await tester.pumpWidget(
        MaterialApp(
          home: VrDevicePairingPage(
            service: service,
            startBluetooth: () async =>
                throw const VrBlePeripheralUnsupportedException(
                  'Esta integración del SDK no incluye un plugin periférico BLE GATT para el rol Visor (registra VrBleGattPeripheralAdapter o el canal dev.neom.ble/gatt_server).',
                  isBackendMissing: true,
                ),
            onCompleted: (_) {},
          ),
        ),
      );
      await tester.pump();

      await tester.tap(find.text('Activar vínculo Bluetooth'));
      await tester.pumpAndSettle();

      expect(
        find.textContaining('dev.neom.ble/gatt_server'),
        findsOneWidget,
      );
      expect(
        find.textContaining('Actívalo y permite Dispositivos cercanos'),
        findsNothing,
      );
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  test(
    'event stream error during pending startDuplexService invalidates start and restores listener on retry (SAIA-004 P2.1)',
    () async {
      final gatt = _FakeGattPeripheral();
      final pendingStart = Completer<bool>();
      gatt.pendingStart = pendingStart;
      final adapter = StreamController<BluetoothAdapterState>.broadcast(
        sync: true,
      );
      final controller = VrRemoteControllerService();
      final host = VrBleHost(
        controller,
        gatt: gatt,
        adapterStates: adapter.stream,
        prepareBluetooth: () async {},
      );
      addTearDown(() async {
        await host.dispose();
        controller.dispose();
        await adapter.close();
        await gatt.incoming.close();
      });

      final firstAttempt = host.start();
      final rejected = expectLater(firstAttempt, throwsStateError);
      for (var i = 0; i < 8; i++) {
        await Future<void>.delayed(Duration.zero);
      }
      expect(gatt.listenCount, 1);

      // Stream faults while native startDuplexService is still awaiting.
      gatt.incoming.addError(StateError('native event stream fault'));
      pendingStart.complete(true);
      await rejected;
      for (var i = 0; i < 8; i++) {
        await Future<void>.delayed(Duration.zero);
      }

      expect(gatt.published, isFalse);
      expect(gatt.advertising, isFalse);
      expect(host.syncingPeerListenable.value, isFalse);

      // Subsequent start() must re-attach listener and receive peer events.
      await host.start();
      expect(gatt.listenCount, 2);
      expect(gatt.published, isTrue);
      expect(gatt.advertising, isTrue);

      gatt.incoming.add(
        const VrBleGattEvent(
          type: VrBleGattEventType.duplexClientSubscribed,
          deviceId: 'peer-after-retry',
          mtu: 64,
        ),
      );
      expect(host.syncingPeerListenable.value, isTrue);
    },
  );

  test(
    'event stream close during pending startDuplexService invalidates start and re-subscribes cleanly on retry (SAIA-004 P2.1b)',
    () async {
      final gatt = _FakeGattPeripheral();
      final pendingStart = Completer<bool>();
      gatt.pendingStart = pendingStart;
      final adapter = StreamController<BluetoothAdapterState>.broadcast(
        sync: true,
      );
      final controller = VrRemoteControllerService();
      final host = VrBleHost(
        controller,
        gatt: gatt,
        adapterStates: adapter.stream,
        prepareBluetooth: () async {},
      );
      addTearDown(() async {
        await host.dispose();
        controller.dispose();
        await adapter.close();
        await gatt.incoming.close();
      });

      final firstAttempt = host.start();
      final rejected = expectLater(firstAttempt, throwsStateError);
      for (var i = 0; i < 8; i++) {
        await Future<void>.delayed(Duration.zero);
      }
      expect(gatt.listenCount, 1);

      await gatt.closeAndReplaceStream();
      pendingStart.complete(true);
      await rejected;
      for (var i = 0; i < 8; i++) {
        await Future<void>.delayed(Duration.zero);
      }

      expect(gatt.published, isFalse);
      expect(gatt.advertising, isFalse);

      await host.start();
      expect(gatt.listenCount, 2);
      expect(gatt.published, isTrue);
      expect(gatt.advertising, isTrue);
    },
  );

  test(
    'custom VrBleGattPeripheralAdapter with isSupported == false and custom prepareBluetooth fails uniformly before prepare or events (SAIA-004 P2.2)',
    () async {
      final gatt = _FakeGattPeripheral(supported: false);
      final controller = VrRemoteControllerService();
      var prepareCalls = 0;
      final host = VrBleHost(
        controller,
        gatt: gatt,
        prepareBluetooth: () async {
          prepareCalls++;
          throw StateError('Permisos denegados no deben ocultarse ni correr antes de isSupported');
        },
      );
      addTearDown(() async {
        await host.dispose();
        controller.dispose();
        await gatt.incoming.close();
      });

      await expectLater(
        host.start(),
        throwsA(
          isA<VrBlePeripheralUnsupportedException>().having(
            (e) => e.isBackendMissing,
            'isBackendMissing',
            isFalse,
          ),
        ),
      );
      expect(prepareCalls, 0);
      expect(gatt.listenCount, 0);
      expect(gatt.published, isFalse);
    },
  );

  test(
    'VrHybridBleUdp 2D mode upgrades to 67-byte zero-JSON VrCompactGamepadFrame with multi-edge ACK and BLE burst coalescing (C-SYNC-01)',
    () async {
      const token = 'hybrid-compact-gamepad-67b-test-token';
      late VrBlePacketLink hostBle;
      late VrBlePacketLink clientBle;

      hostBle = VrBlePacketLink(
        writeChunk: (chunk) async => clientBle.receive(chunk),
        onClose: () async {},
      )..enableSinglePacketState();
      clientBle = VrBlePacketLink(
        writeChunk: (chunk) async => hostBle.receive(chunk),
        onClose: () async {},
      )..enableSinglePacketState();

      final service = VrRemoteControllerService(sessionToken: token);
      VrHybridBleUdpHostLink? hybridHost;

      VrBleHostPeer(
        link: hostBle,
        sessionToken: token,
        onAuthenticated: (authenticatedBle) {
          hybridHost = VrHybridBleUdpHostLink(
            bleLink: authenticatedBle,
            sessionToken: token,
            overrideLanIps: const ['127.0.0.1'],
            bindAddress: InternetAddress.loopbackIPv4,
            localCapabilitiesSummary: const {
              'maker': 'Google',
              'model': 'Pixel 9 Pro',
              'cls': 'flagship',
              'wifiOn': true,
              'wifi5': true,
              'freqMhz': 5180,
              'maxHz': 120,
            },
          );
          return service.attachControllerLink(
            hybridHost!,
            sessionToken: token,
          );
        },
      );

      final clientPeer = VrBleClientPeer(link: clientBle, sessionToken: token);
      final readyBle = await clientPeer.ready;
      final hybridClient = VrHybridBleUdpClientLink(
        bleLink: readyBle,
        sessionToken: token,
        bindAddress: InternetAddress.loopbackIPv4,
        localCapabilitiesSummary: const {
          'maker': 'Motorola',
          'model': 'Edge',
          'cls': 'flagship',
          'wifiOn': true,
          'wifi5': true,
          'freqMhz': 5180,
          'maxHz': 120,
          'gyro': true,
        },
      );
      final sub = hybridClient.messages.listen((_) {});
      for (var i = 0; i < 30 && !hybridClient.isUdpActive; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }
      expect(hybridClient.isUdpActive, isTrue);
      expect(hybridClient.supportsCompactGamepadFrames, isTrue);
      expect(VrHybridWireConstants.compactGamepadDatagramBytes, 67);

      final baseState = service.latestState;
      // 1. Neutral mode-revision ACK frame first (matches PhoneControllerPage protocol)
      hybridClient.add(
        VrCompactGamepadFrame(
          sequence: 1,
          senderTimestampMicroseconds: 8000,
          orientation: baseState.orientation,
          angularVelocity: baseState.angularVelocity,
          pointerPoseReady: true,
          hostModeRevision: 0,
        ),
      );
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(service.latestState.pointerPoseReady, isTrue);

      // 2. Full 67-byte zero-JSON gameplay + 16-bit laser + discrete edge ACK
      hybridClient.add(
        VrCompactGamepadFrame(
          sequence: 2,
          senderTimestampMicroseconds: 16000,
          orientation: baseState.orientation,
          angularVelocity: baseState.angularVelocity,
          stickX: 0.625,
          stickY: -0.375,
          laserX: 0.3125,
          laserY: -0.21875,
          laserSlideActive: true,
          pointerPoseReady: true,
          btnA: true,
          btnZL: true,
          btnZR: true,
          moveAtEdge: true,
          hostModeRevision: 0,
        ),
      );
      await Future<void>.delayed(const Duration(milliseconds: 35));

      expect(service.latestState.btnA, isTrue);
      expect(service.latestState.btnZL, isTrue);
      expect(service.latestState.btnZR, isTrue);
      expect(service.latestState.pointerPoseReady, isTrue);
      expect(service.latestState.moveAtEdge, isTrue);
      expect(service.latestState.laserX, closeTo(0.3125, 0.002));
      expect(service.latestState.laserY, closeTo(-0.21875, 0.002));
      expect(hybridClient.pendingDiscreteEdgeCount, 0);

      // Post-auth BLE burst (>16 queued packets before listener attaches) coalesces
      // stale state frames instead of throwing non-retryable protocol rejection.
      late VrBlePacketLink burstLink;
      late VrBlePacketLink serverSide;
      burstLink = VrBlePacketLink(
        writeChunk: (chunk) async => serverSide.receive(chunk),
        onClose: () async {},
      )..enableSinglePacketState();
      serverSide = VrBlePacketLink(
        writeChunk: (chunk) async => burstLink.receive(chunk),
        onClose: () async {},
      )..enableSinglePacketState();
      VrControllerLink? authedServer;
      VrBleHostPeer(
        link: serverSide,
        sessionToken: token,
        onAuthenticated: (l) {
          authedServer = l;
          return true;
        },
      );
      final authedClient = await VrBleClientPeer(
        link: burstLink,
        sessionToken: token,
      ).ready;
      expect(authedServer, isNotNull);
      for (var i = 1; i <= 22; i++) {
        authedClient.add(jsonEncode({'sequence': i, 'stickX': i / 25.0}));
      }
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(authedServer!.isOpen, isTrue);
      final receivedAfterBurst = <Object?>[];
      final burstSub = authedServer!.messages.listen(receivedAfterBurst.add);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(receivedAfterBurst, isNotEmpty);

      await burstSub.cancel();
      await authedClient.close();
      await authedServer!.close();
      await sub.cancel();
      await hybridClient.close();
      await hybridHost!.close();
      service.dispose();
    },
  );
}
