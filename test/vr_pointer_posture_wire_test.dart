import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vrlizate_ble/vrlizate_ble.dart';

const _token = 'unit-test-pointer-posture-session-token';

String _state(
  int sequence,
  bool ready, {
  String mode = 'joystick',
  bool zl = false,
  bool zr = false,
}) => jsonEncode({
  'sequence': sequence,
  'mode': mode,
  'pointerPoseReady': ready,
  'btnZL': zl,
  'btnZR': zr,
  'stickX': 0.25,
});

Future<void> _flush() async {
  for (var i = 0; i < 16; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

void _deliver(VrBlePacketLink link, Map<String, Object?> control) {
  final packet = VrBleWireCodec.encode(jsonEncode(control));
  for (final chunk in VrBleWireCodec.frame(packet)) {
    link.receive(chunk);
  }
}

class _BlePair {
  _BlePair(this.host, this.client);
  final VrBlePacketLink host;
  final VrBlePacketLink client;

  Future<void> close() async {
    await client.close();
    await host.close();
  }
}

Future<_BlePair> _pair({
  bool hostSupportsPosture = true,
  bool clientSupportsPosture = true,
  bool hostSupportsShoulders = true,
  bool clientSupportsShoulders = true,
}) async {
  late VrBlePacketLink host;
  late VrBlePacketLink client;
  host = VrBlePacketLink(
    writeChunk: (chunk) async => client.receive(chunk),
    onClose: () async {},
  )..enableSinglePacketState();
  client = VrBlePacketLink(
    writeChunk: (chunk) async => host.receive(chunk),
    onClose: () async {},
  )..enableSinglePacketState();
  final clientPeer = VrBleClientPeer(
    link: client,
    sessionToken: _token,
    supportsPointerPosture: clientSupportsPosture,
    supportsShoulderButtons: clientSupportsShoulders,
  );
  VrBleHostPeer(
    link: host,
    sessionToken: _token,
    supportsPointerPosture: hostSupportsPosture,
    supportsShoulderButtons: hostSupportsShoulders,
    onAuthenticated: (_) => true,
  );
  await clientPeer.ready.timeout(const Duration(seconds: 2));
  return _BlePair(host, client);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'negotiated readiness uses only mode bit2 and preserves 21-byte ABI',
    () {
      for (final mode in ['joystick', 'driving', 'nes']) {
        final legacy = VrBleWireCodec.encode(_state(7, true, mode: mode));
        final ready = VrBleWireCodec.encode(
          _state(7, true, mode: mode),
          allowPointerPosture: true,
        );
        final inactive = VrBleWireCodec.encode(
          _state(7, false, mode: mode),
          allowPointerPosture: true,
        );
        expect(legacy.length, 21);
        expect(ready.length, 21);
        expect(inactive, orderedEquals(legacy));
        for (var i = 0; i < ready.length; i++) {
          expect(ready[i], i == 3 ? legacy[i] | 0x04 : legacy[i]);
        }
        final decoded =
            jsonDecode(VrBleWireCodec.decode(ready, allowPointerPosture: true))
                as Map;
        expect(decoded['mode'], mode);
        expect(decoded['pointerPoseReady'], isTrue);
        expect(decoded['sequence'], 7);
        expect(decoded['stickX'] as num, closeTo(0.25, 0.01));
      }
    },
  );

  test(
    'legacy default drops readiness and negotiated decoder fails closed',
    () {
      final legacy = VrBleWireCodec.encode(_state(1, true));
      expect(legacy[3], 0);
      for (final allow in [false, true]) {
        final decoded =
            jsonDecode(
                  VrBleWireCodec.decode(legacy, allowPointerPosture: allow),
                )
                as Map;
        expect(decoded['pointerPoseReady'], isFalse);
      }
      final extended = VrBleWireCodec.encode(
        _state(1, true),
        allowPointerPosture: true,
      );
      expect(() => VrBleWireCodec.decode(extended), throwsFormatException);
    },
  );

  test('posture encoding rejects non-bools with either negotiated state', () {
    for (final allow in [false, true]) {
      for (final invalid in [null, 0, 1, 'true', [], {}]) {
        expect(
          () => VrBleWireCodec.encode(
            jsonEncode({'sequence': 1, 'pointerPoseReady': invalid}),
            allowPointerPosture: allow,
          ),
          throwsFormatException,
        );
      }
    }
  });

  test('decode rejects unknown mode and all unassigned mode-byte bits', () {
    final state = VrBleWireCodec.encode(_state(1, false));
    for (final invalid in [3, 7, 8, 16, 32, 64, 128, 255]) {
      final malformed = Uint8List.fromList(state)..[3] = invalid;
      expect(
        () => VrBleWireCodec.decode(malformed, allowPointerPosture: true),
        throwsFormatException,
      );
    }
  });

  test('posture and edge-turn flags remain independent after negotiation', () {
    final packet = VrBleWireCodec.encode(
      jsonEncode({
        'sequence': 5,
        'mode': 'joystick',
        'moveAtEdge': true,
        'pointerPoseReady': true,
      }),
      allowEdgeTurnIntent: true,
      allowPointerPosture: true,
    );
    expect(packet[2] & 0x80, 0x80);
    expect(packet[3], 4);
    final decoded =
        jsonDecode(
              VrBleWireCodec.decode(
                packet,
                allowEdgeTurnIntent: true,
                allowPointerPosture: true,
              ),
            )
            as Map;
    expect(decoded['moveAtEdge'], isTrue);
    expect(decoded['pointerPoseReady'], isTrue);
  });

  test(
    'both authenticated peers negotiate readiness and deliver transitions',
    () async {
      final pair = await _pair();
      addTearDown(pair.close);
      final messages = <Map>[];
      final sub = pair.host.messages.listen((data) {
        messages.add(jsonDecode(data! as String) as Map);
      });
      addTearDown(sub.cancel);
      expect(pair.host.pointerPostureEnabled, isTrue);
      expect(pair.client.pointerPostureEnabled, isTrue);
      pair.client.add(_state(1, true));
      pair.client.add(_state(2, false));
      await _flush();
      expect(messages.map((m) => m['sequence']), [1, 2]);
      expect(messages.map((m) => m['pointerPoseReady']), [true, false]);
    },
  );

  for (final oldHost in [true, false]) {
    test('one older peer never enables posture: oldHost=$oldHost', () async {
      final pair = await _pair(
        hostSupportsPosture: !oldHost,
        clientSupportsPosture: oldHost,
      );
      addTearDown(pair.close);
      final messages = <Map>[];
      final sub = pair.host.messages.listen((data) {
        messages.add(jsonDecode(data! as String) as Map);
      });
      addTearDown(sub.cancel);
      expect(pair.host.pointerPostureEnabled, isFalse);
      expect(pair.client.pointerPostureEnabled, isFalse);
      pair.client.add(_state(1, true));
      await _flush();
      expect(messages.single['mode'], 'joystick');
      expect(messages.single['pointerPoseReady'], isFalse);
    });
  }

  test(
    'client rejects non-bool posture capability before authentication',
    () async {
      final link = VrBlePacketLink(
        writeChunk: (_) async {},
        onClose: () async {},
      );
      addTearDown(link.close);
      final client = VrBleClientPeer(link: link, sessionToken: _token);
      final rejected = expectLater(client.ready, throwsA(isA<Exception>()));
      _deliver(link, {
        'type': 'challenge',
        'nonce': base64UrlEncode(List.filled(32, 0)),
        'pointerPostureV1': 'true',
      });
      await rejected;
      expect(link.pointerPostureEnabled, isFalse);
      expect(link.isOpen, isFalse);
    },
  );

  test(
    'host rejects malformed posture capability even with optional field',
    () async {
      final link = VrBlePacketLink(
        writeChunk: (_) async {},
        onClose: () async {},
      );
      addTearDown(link.close);
      var attached = false;
      VrBleHostPeer(
        link: link,
        sessionToken: _token,
        onAuthenticated: (_) => attached = true,
      );
      _deliver(link, {
        'type': 'authenticate',
        'nonce': base64UrlEncode(List.filled(32, 0)),
        'pointerPostureV1': 1,
        'proof': 'not-a-valid-proof',
      });
      await _flush();
      expect(attached, isFalse);
      expect(link.isOpen, isFalse);
      expect(link.pointerPostureEnabled, isFalse);
    },
  );

  test(
    'client rejects unsolicited ready capability with otherwise valid proof',
    () async {
      final outgoing = <Map>[];
      final reader = VrBleReassembler();
      final link = VrBlePacketLink(
        writeChunk: (chunk) async {
          final packet = reader.add(chunk);
          if (packet != null) {
            outgoing.add(jsonDecode(VrBleWireCodec.decode(packet)) as Map);
          }
        },
        onClose: () async {},
      );
      addTearDown(link.close);
      final client = VrBleClientPeer(
        link: link,
        sessionToken: _token,
        supportsPointerPosture: false,
      );
      final rejected = expectLater(client.ready, throwsA(isA<Exception>()));
      final serverNonce = base64UrlEncode(List.filled(32, 0));
      _deliver(link, {'type': 'challenge', 'nonce': serverNonce});
      await _flush();
      final authentication = outgoing.single;
      expect(authentication.containsKey('pointerPostureV1'), isFalse);
      final proof = Hmac(sha256, utf8.encode(_token))
          .convert(
            utf8.encode(
              'vrlizate-ble-v1/parent/$serverNonce/${authentication['nonce']}',
            ),
          )
          .toString();
      _deliver(link, {
        'type': 'ready',
        'proof': proof,
        'pointerPostureV1': true,
      });
      await rejected;
      expect(link.pointerPostureEnabled, isFalse);
      expect(link.isOpen, isFalse);
    },
  );

  test('BLE coalescer keeps both posture edges FIFO and reliable', () async {
    final gate = Completer<void>();
    final chunks = <Uint8List>[];
    final reliabilityLog = <bool>[];
    final writer = VrBlePacketWriter(
      allowSinglePacketState: true,
      writeChunk: (_) async => fail('expected the reliability-aware writer'),
      writeChunkWithReliability: (chunk, {required bool reliable}) async {
        chunks.add(Uint8List.fromList(chunk));
        reliabilityLog.add(reliable);
        if (chunks.length == 1) await gate.future;
      },
      onError: (error) => fail('unexpected writer error: $error'),
    )..allowPointerPosture = true;
    addTearDown(writer.close);
    writer.add(_state(0, false));
    writer.add(_state(1, false));
    writer.add(_state(2, true));
    writer.add(_state(3, false));
    writer.add(_state(4, false));
    gate.complete();
    await _flush();
    final reader = VrBleReassembler(allowSinglePacketState: true);
    final decoded = chunks.map((chunk) {
      final packet = reader.add(chunk)!;
      return jsonDecode(
            VrBleWireCodec.decode(packet, allowPointerPosture: true),
          )
          as Map;
    }).toList();
    expect(decoded.map((m) => m['sequence']), [0, 1, 2, 4]);
    expect(decoded.map((m) => m['pointerPoseReady']), [
      false,
      false,
      true,
      false,
    ]);
    expect(reliabilityLog, [true, false, true, true]);
  });

  test('shoulders negotiate in both directions across legacy peers', () async {
    for (final (hostSupports, clientSupports) in const [
      (true, true),
      (false, true),
      (true, false),
    ]) {
      final pair = await _pair(
        hostSupportsShoulders: hostSupports,
        clientSupportsShoulders: clientSupports,
      );
      try {
        final enabled = hostSupports && clientSupports;
        expect(pair.host.shoulderButtonsEnabled, enabled);
        expect(pair.client.shoulderButtonsEnabled, enabled);
        final received = <Map>[];
        final inbound = pair.host.messages.listen((text) {
          received.add(jsonDecode(text! as String) as Map);
        });
        pair.client.add(_state(1, true, zl: true));
        // Without negotiated shoulders these are ordinary snapshots and may
        // coalesce. With capability enabled the burst must retain each edge.
        if (!enabled) await _flush();
        pair.client.add(_state(2, true, zr: true));
        if (!enabled) await _flush();
        pair.client.add(_state(3, true));
        await _flush();
        expect(received.map((event) => event['sequence']), [1, 2, 3]);
        expect(received.map((event) => event['btnZL'] == true), [
          enabled,
          false,
          false,
        ]);
        expect(received.map((event) => event['btnZR'] == true), [
          false,
          enabled,
          false,
        ]);
        expect(
          received.every((event) => event['pointerPoseReady'] == true),
          isTrue,
        );
        await inbound.cancel();
      } finally {
        await pair.close();
      }
    }
  });

  test(
    'shoulder flags retain the 21 byte envelope and require negotiation',
    () {
      final ordinary = VrBleWireCodec.encode(_state(3, false));
      final dropped = VrBleWireCodec.encode(
        _state(3, false, zl: true, zr: true),
      );
      expect(dropped, ordinary);
      final allowed = VrBleWireCodec.encode(
        _state(3, false, zl: true, zr: true),
        allowShoulderButtons: true,
      );
      expect(allowed.length, 21);
      expect(allowed[3], ordinary[3] | 0x18);
      expect(() => VrBleWireCodec.decode(allowed), throwsFormatException);
      final decoded =
          jsonDecode(VrBleWireCodec.decode(allowed, allowShoulderButtons: true))
              as Map;
      expect(decoded['btnZL'], isTrue);
      expect(decoded['btnZR'], isTrue);
    },
  );

  test(
    'authenticated hybrid UDP preserves readiness and shoulders in 43B envelope',
    () async {
      final pair = await _pair();
      addTearDown(pair.close);
      const capabilities = <String, Object?>{
        'maker': 'test',
        'model': 'test-device',
        'cls': 'flagship',
        'wifiOn': true,
        'wifi5': true,
        'freqMhz': 5180,
        'maxHz': 120,
      };
      final host = VrHybridBleUdpHostLink(
        bleLink: pair.host,
        sessionToken: _token,
        overrideLanIps: const ['127.0.0.1'],
        bindAddress: InternetAddress.loopbackIPv4,
        localCapabilitiesSummary: capabilities,
      );
      final client = VrHybridBleUdpClientLink(
        bleLink: pair.client,
        sessionToken: _token,
        bindAddress: InternetAddress.loopbackIPv4,
        localCapabilitiesSummary: capabilities,
      );
      addTearDown(host.close);
      addTearDown(client.close);
      final messages = <Map>[];
      final hostSub = host.messages.listen((data) {
        messages.add(jsonDecode(data! as String) as Map);
      });
      final clientSub = client.messages.listen((_) {});
      addTearDown(hostSub.cancel);
      addTearDown(clientSub.cancel);
      for (var i = 0; i < 100 && !client.isUdpActive; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }
      expect(client.isUdpActive, isTrue);
      expect(client.pointerPostureEnabled, isTrue);
      expect(host.pointerPostureEnabled, isTrue);
      expect(VrHybridWireConstants.stateDatagramBytes, 43);
      client.add(_state(1, true, zl: true, zr: true));
      for (var i = 0; i < 100 && messages.isEmpty; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 5));
      }
      expect(messages.single['pointerPoseReady'], isTrue);
      expect(messages.single['btnZL'], isTrue);
      expect(messages.single['btnZR'], isTrue);
      client.add(_state(2, false));
      for (var i = 0; i < 100 && messages.length < 2; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 5));
      }
      expect(messages.map((m) => m['sequence']), [1, 2]);
      expect(messages.last['pointerPoseReady'], isFalse);
      expect(messages.last['btnZL'], isFalse);
      expect(messages.last['btnZR'], isFalse);
    },
  );
}
