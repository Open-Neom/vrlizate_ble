import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:vrlizate/vrlizate.dart'
    show VrCompactGamepadCodec, VrCompactGamepadFrame;
import 'package:vrlizate_joystick/vrlizate_joystick.dart';

import 'vr_ble_peer_capabilities.dart';
import 'vr_ble_session.dart';
import 'vr_ble_wire.dart';

/// Internal post-authentication BLE control message types consumed by the
/// hybrid wrapper and never forwarded to application state parsers.
abstract final class VrHybridWireConstants {
  static const offerType = 'vrlizate.hybridOffer';
  static const peerCapsType = 'vrlizate.peerCaps';
  static const linkAdviceType = 'vrlizate.linkAdvice';

  static const pingKind = 1;
  static const pongKind = 2;
  static const stateKind = 3;
  static const compactGamepadKind = 4;
  static const stateAckKind = 5;

  static const pingPongPacketBytes =
      33; // 4 magic + 1 kind + 4 seq + 8 us + 16 mac
  static const stateDatagramBytes =
      43; // 4 magic + 1 kind + 1 edge + 21 state + 16 mac
  static const compactGamepadDatagramBytes =
      67; // 4 magic + 1 kind + 46 compactGamepad + 16 mac
  static const stateAckDatagramBytes =
      25; // 4 magic + 1 kind + 4 ackSeq + 16 mac
  static const hmacTagBytes = 16;
}

bool _isNewerSequence32(int candidate, int previous) {
  final delta = (candidate - previous) & 0xFFFFFFFF;
  return delta != 0 && delta < 0x80000000;
}

bool _isSequenceAtLeast32(int candidate, int target) {
  final delta = (candidate - target) & 0xFFFFFFFF;
  return delta < 0x80000000;
}

List<int> _deriveHybridUdpKey(String sessionToken, String offerNonce) => Hmac(
  sha256,
  utf8.encode(sessionToken),
).convert(utf8.encode('vrlizate-hybrid-udp-v1/$offerNonce')).bytes;

Uint8List _computeTag(List<int> key, Uint8List body) {
  final digest = Hmac(sha256, key).convert(body).bytes;
  return Uint8List.fromList(
    digest.sublist(0, VrHybridWireConstants.hmacTagBytes),
  );
}

bool _verifyTagConstantTime(
  List<int> key,
  Uint8List datagram,
  int payloadEndOffset,
) {
  if (datagram.length !=
      payloadEndOffset + VrHybridWireConstants.hmacTagBytes) {
    return false;
  }
  final body = Uint8List.sublistView(datagram, 0, payloadEndOffset);
  final expected = Hmac(sha256, key).convert(body).bytes;
  var diff = 0;
  for (var i = 0; i < VrHybridWireConstants.hmacTagBytes; i++) {
    diff |= datagram[payloadEndOffset + i] ^ expected[i];
  }
  return diff == 0;
}

bool _hasMagic(Uint8List d) =>
    d.length >= 5 &&
    d[0] == 0x56 && // 'V'
    d[1] == 0x52 && // 'R'
    d[2] == 0x55 && // 'U'
    d[3] == 0x31; // '1'

String _freshOfferNonce() {
  final rng = math.Random.secure();
  final bytes = List<int>.generate(16, (_) => rng.nextInt(256));
  return base64UrlEncode(bytes);
}

Future<List<String>> _discoverLocalLanIps() async {
  try {
    final interfaces = await NetworkInterface.list(
      type: InternetAddressType.IPv4,
      includeLinkLocal: false,
    );
    final candidates = <VrLocalAddressCandidate>[];
    for (final iface in interfaces) {
      for (final addr in iface.addresses) {
        if (!addr.isLoopback) {
          candidates.add(VrLocalAddressCandidate(iface.name, addr.address));
        }
      }
    }
    return VrLocalNetworkAddress.selectAll(candidates, limit: 4);
  } catch (_) {
    return const <String>[];
  }
}

VrControllerFastTransport _classifyBleTransport(VrControllerLink ble) {
  if (ble is VrBlePacketLink && ble.singlePacketStateEnabled) {
    return VrControllerFastTransport.bleSinglePacket;
  }
  return VrControllerFastTransport.bleFragmented;
}

VrControllerFastTransport _classifyUdpTransport(
  Map<String, Object?>? visorSummary,
  Map<String, Object?>? joystickSummary,
) {
  final vFreq = visorSummary?['freqMhz'] as int?;
  final jFreq = joystickSummary?['freqMhz'] as int?;
  if ((vFreq != null && vFreq >= 2400 && vFreq < 2500) ||
      (jFreq != null && jFreq >= 2400 && jFreq < 2500)) {
    return VrControllerFastTransport.udp24Ghz;
  }
  return VrControllerFastTransport.udp5Ghz;
}

int _negotiatedControllerHz({
  required VrControllerFastTransport transport,
  Map<String, Object?>? visorSummary,
  Map<String, Object?>? joystickSummary,
}) {
  if (transport != VrControllerFastTransport.udp5Ghz) return 60;
  final visorPro =
      visorSummary?['cls'] == 'flagship' &&
      ((visorSummary?['maxHz'] as int?) ?? 60) >= 115;
  final joyPro =
      joystickSummary?['cls'] == 'flagship' &&
      ((joystickSummary?['maxHz'] as int?) ?? 60) >= 115;
  return (visorPro && joyPro) ? 120 : 60;
}

/// Visor-side wrapper around an authenticated BLE link that opens an ephemeral
/// HMAC-authenticated UDP fast path and deduplicates monotonic state sequences
/// across BLE and UDP seamlessly.
class VrHybridBleUdpHostLink
    implements VrObservableControllerLink, VrCompactGamepadAckSink {
  VrHybridBleUdpHostLink({
    required VrControllerLink bleLink,
    required this.sessionToken,
    Map<String, Object?>? localCapabilitiesSummary,
    this.overrideLanIps,
    InternetAddress? bindAddress,
  }) : _ble = bleLink,
       _visorSummary = localCapabilitiesSummary,
       _bindAddress = bindAddress ?? InternetAddress.anyIPv4 {
    _quality = ValueNotifier<VrControllerLinkQuality>(
      VrControllerLinkQuality(
        transport: _classifyBleTransport(_ble),
        canCarryVideoCast: false,
      ),
    );
    _messages = StreamController<Object?>(
      sync: true,
      onListen: _startListening,
      onPause: () => _bleSub?.pause(),
      onResume: () => _bleSub?.resume(),
      onCancel: () => unawaited(close()),
    );
  }

  final VrControllerLink _ble;
  final String sessionToken;
  Map<String, Object?>? _visorSummary;
  Map<String, Object?>? _joystickSummary;
  final List<String>? overrideLanIps;
  final InternetAddress _bindAddress;
  final String _offerNonce = _freshOfferNonce();
  late final List<int> _udpKey = _deriveHybridUdpKey(sessionToken, _offerNonce);
  late final StreamController<Object?> _messages;
  late final ValueNotifier<VrControllerLinkQuality> _quality;
  StreamSubscription<Object?>? _bleSub;
  RawDatagramSocket? _udpSocket;
  Timer? _udpWatchdog;
  final Stopwatch _clock = Stopwatch()..start();
  int? _lastUdpPacketUs;
  int? _lastDeliveredStateSequence;
  InternetAddress? _lastClientAddress;
  int _lastClientPort = 0;
  bool _open = true;
  bool _udpReceivingStates = false;

  int? get boundUdpPort => _udpSocket?.port;

  /// Diagnostic capability only, never inferred from traffic or device model.
  bool get pointerPostureEnabled =>
      _ble is VrBlePacketLink && _ble.pointerPostureEnabled;

  bool get _shoulderButtonsEnabled =>
      _ble is VrBlePacketLink && _ble.shoulderButtonsEnabled;

  @override
  bool get isOpen => _open && _ble.isOpen;

  @override
  Stream<Object?> get messages => _messages.stream;

  @override
  ValueListenable<VrControllerLinkQuality> get linkQualityListenable =>
      _quality;

  void _startListening() {
    if (_bleSub != null || !_open) return;
    _bleSub = _ble.messages.listen(
      _onBleMessage,
      onError: (Object error, StackTrace stack) {
        if (!_messages.isClosed) _messages.addError(error, stack);
      },
      onDone: () => unawaited(close()),
      cancelOnError: true,
    );
    unawaited(_openUdpAndSendOffer());
  }

  Future<void> _openUdpAndSendOffer() async {
    if (!_open) return;
    _visorSummary ??= await VrBlePeerCapabilities.resolve();
    List<String> ips = overrideLanIps ?? await _discoverLocalLanIps();
    if (!_open) return;
    var udpPort = 0;
    if (ips.isNotEmpty) {
      try {
        final socket = await RawDatagramSocket.bind(_bindAddress, 0);
        if (!_open) {
          socket.close();
          return;
        }
        _udpSocket = socket;
        udpPort = socket.port;
        socket.listen(_onUdpSocketEvent, onError: (_) {});
        _udpWatchdog = Timer.periodic(
          const Duration(milliseconds: 250),
          (_) => _checkUdpFreshness(),
        );
      } catch (_) {
        ips = const <String>[];
      }
    }
    _recomputeQuality();
    if (!_open || !_ble.isOpen) return;
    try {
      _ble.add(
        jsonEncode({
          'type': VrHybridWireConstants.offerType,
          'v': 1,
          'udpPort': udpPort,
          'ips': ips,
          'nonce': _offerNonce,
          'compactGamepadV1': true,
          if (_visorSummary != null) 'caps': _visorSummary,
        }),
      );
    } catch (_) {}
  }

  void _checkUdpFreshness() {
    if (!_open || !_udpReceivingStates) return;
    final lastUs = _lastUdpPacketUs;
    if (lastUs != null && _clock.elapsedMicroseconds - lastUs > 700000) {
      _udpReceivingStates = false;
      _recomputeQuality();
    }
  }

  void _onUdpSocketEvent(RawSocketEvent event) {
    if (!_open || event != RawSocketEvent.read) return;
    final socket = _udpSocket;
    if (socket == null) return;
    Datagram? dg;
    while ((dg = socket.receive()) != null) {
      _handleUdpDatagram(socket, dg!);
    }
  }

  VrCompactGamepadFrame _sanitizeCompactCapabilities(VrCompactGamepadFrame f) {
    final allowEdge = _ble is! VrBlePacketLink || _ble.edgeTurnIntentEnabled;
    final allowPosture = pointerPostureEnabled;
    final allowShoulders = _shoulderButtonsEnabled;
    if ((allowEdge || !f.moveAtEdge) &&
        (allowPosture || !f.pointerPoseReady) &&
        (allowShoulders || (!f.btnZL && !f.btnZR))) {
      return f;
    }
    return VrCompactGamepadFrame(
      sequence: f.sequence,
      senderTimestampMicroseconds: f.senderTimestampMicroseconds,
      orientation: f.orientation,
      angularVelocity: f.angularVelocity,
      stickX: f.stickX,
      stickY: f.stickY,
      lookX: f.lookX,
      lookY: f.lookY,
      laserX: f.laserX,
      laserY: f.laserY,
      steering: f.steering,
      drivingTilt: f.drivingTilt,
      throttle: f.throttle,
      brake: f.brake,
      modeIndex: f.modeIndex,
      hostModeRevision: f.hostModeRevision,
      trigger: f.trigger,
      action: f.action,
      btnA: f.btnA,
      btnB: f.btnB,
      btnX: f.btnX,
      btnY: f.btnY,
      btnL: f.btnL,
      btnR: f.btnR,
      btnZL: allowShoulders && f.btnZL,
      btnZR: allowShoulders && f.btnZR,
      btnGrip: f.btnGrip,
      stickClick: f.stickClick,
      recenter: f.recenter,
      moveAtEdge: allowEdge && f.moveAtEdge,
      laserSlideActive: f.laserSlideActive,
      pointerPoseReady: allowPosture && f.pointerPoseReady,
      controllerVisible: f.controllerVisible,
      drivingPaused: f.drivingPaused,
      motionAvailable: f.motionAvailable,
      passthroughActive: f.passthroughActive,
      spatialHudVisible: f.spatialHudVisible,
      passthroughMix: f.passthroughMix,
      rangeMeters: f.rangeMeters,
    );
  }

  void _sendStateAck(int sequence) {
    final socket = _udpSocket;
    final addr = _lastClientAddress;
    if (!_open || socket == null || addr == null || _lastClientPort <= 0) {
      return;
    }
    final body = Uint8List(9)
      ..[0] = 0x56
      ..[1] = 0x52
      ..[2] = 0x55
      ..[3] = 0x31
      ..[4] = VrHybridWireConstants.stateAckKind;
    ByteData.sublistView(body).setUint32(5, sequence & 0xFFFFFFFF, Endian.little);
    final tag = _computeTag(_udpKey, body);
    final ack = Uint8List(VrHybridWireConstants.stateAckDatagramBytes)
      ..setRange(0, 9, body)
      ..setRange(9, 25, tag);
    try {
      socket.send(ack, addr, _lastClientPort);
    } catch (_) {}
  }

  @override
  void acknowledgeCompactGamepadSequence(int sequence) {
    _sendStateAck(sequence);
  }

  void _handleUdpDatagram(RawDatagramSocket socket, Datagram dg) {
    final data = dg.data;
    if (!_hasMagic(data)) return;
    final kind = data[4];
    if (kind == VrHybridWireConstants.pingKind &&
        data.length == VrHybridWireConstants.pingPongPacketBytes) {
      if (!_verifyTagConstantTime(_udpKey, data, 17)) return;
      _lastClientAddress = dg.address;
      _lastClientPort = dg.port;
      if (_udpReceivingStates) {
        _lastUdpPacketUs = _clock.elapsedMicroseconds;
      }
      final pongBody = Uint8List(17)
        ..setRange(0, 4, data)
        ..[4] = VrHybridWireConstants.pongKind
        ..setRange(5, 17, data, 5);
      final tag = _computeTag(_udpKey, pongBody);
      final pong = Uint8List(VrHybridWireConstants.pingPongPacketBytes)
        ..setRange(0, 17, pongBody)
        ..setRange(17, 33, tag);
      try {
        socket.send(pong, dg.address, dg.port);
      } catch (_) {}
      return;
    }

    if (kind == VrHybridWireConstants.compactGamepadKind &&
        data.length == VrHybridWireConstants.compactGamepadDatagramBytes) {
      if (!_verifyTagConstantTime(_udpKey, data, 51)) return;
      final rawFrame = const VrCompactGamepadCodec().tryDecode(
        Uint8List.sublistView(data, 5, 51),
      );
      if (rawFrame == null) return;
      _lastClientAddress = dg.address;
      _lastClientPort = dg.port;
      final frame = _sanitizeCompactCapabilities(rawFrame);
      if (_lastDeliveredStateSequence != null &&
          !_isNewerSequence32(frame.sequence, _lastDeliveredStateSequence!)) {
        _sendStateAck(_lastDeliveredStateSequence!);
        return;
      }
      _lastDeliveredStateSequence = frame.sequence;
      _lastUdpPacketUs = _clock.elapsedMicroseconds;
      if (!_udpReceivingStates) {
        _udpReceivingStates = true;
        _recomputeQuality();
      }
      if (!_messages.isClosed) _messages.add(frame);
      return;
    }

    if (kind == VrHybridWireConstants.stateKind &&
        data.length == VrHybridWireConstants.stateDatagramBytes) {
      if (!_verifyTagConstantTime(_udpKey, data, 27)) return;
      _lastClientAddress = dg.address;
      _lastClientPort = dg.port;
      final allowEdge =
          data[5] == 1 &&
          (_ble is! VrBlePacketLink || _ble.edgeTurnIntentEnabled);
      final statePacket = Uint8List.sublistView(data, 6, 27);
      if (statePacket[0] != 1) return;
      final seq = ByteData.sublistView(statePacket).getUint32(4, Endian.little);
      if (_lastDeliveredStateSequence != null &&
          !_isNewerSequence32(seq, _lastDeliveredStateSequence!)) {
        _sendStateAck(_lastDeliveredStateSequence!);
        return;
      }
      try {
        final json = VrBleWireCodec.decode(
          Uint8List.fromList(statePacket),
          allowEdgeTurnIntent: allowEdge,
          allowPointerPosture: pointerPostureEnabled,
          allowShoulderButtons: _shoulderButtonsEnabled,
        );
        _lastDeliveredStateSequence = seq;
        _lastUdpPacketUs = _clock.elapsedMicroseconds;
        if (!_udpReceivingStates) {
          _udpReceivingStates = true;
          _recomputeQuality();
        }
        _sendStateAck(seq);
        if (!_messages.isClosed) _messages.add(json);
      } catch (_) {
        // Ignore malformed UDP datagrams rather than dropping authenticated BLE.
      }
    }
  }

  void _onBleMessage(Object? data) {
    if (!_open || _messages.isClosed) return;
    if (data is String && data.length <= 2048) {
      try {
        final decoded = jsonDecode(data);
        if (decoded is Map<String, dynamic>) {
          final type = decoded['type'];
          if (type == VrHybridWireConstants.peerCapsType) {
            final caps = decoded['caps'];
            if (caps is Map) {
              _joystickSummary = caps.cast<String, Object?>();
              _recomputeQuality();
            }
            return;
          }
          if (type == null && decoded['sequence'] is int) {
            final seq = decoded['sequence'] as int;
            if (_lastDeliveredStateSequence != null &&
                !_isNewerSequence32(seq, _lastDeliveredStateSequence!)) {
              return;
            }
            _lastDeliveredStateSequence = seq;
          }
        }
      } catch (_) {}
    }
    _messages.add(data);
  }

  void _recomputeQuality() {
    if (!_open) return;
    final transport = _udpReceivingStates
        ? _classifyUdpTransport(_visorSummary, _joystickSummary)
        : _classifyBleTransport(_ble);
    final hz = _negotiatedControllerHz(
      transport: transport,
      visorSummary: _visorSummary,
      joystickSummary: _joystickSummary,
    );
    final advisory = VrLinkPerformanceAdvisor.evaluate(
      transport: transport,
      visorSummary: _visorSummary,
      joystickSummary: _joystickSummary,
    );
    final next = VrControllerLinkQuality(
      transport: transport,
      recommendedHz: hz,
      canCarryVideoCast: _udpReceivingStates,
      peerSupportsMotion: _joystickSummary?['gyro'] != false,
      peerSupportsConcurrentCameras: _joystickSummary?['cam3'] == true,
      peerDeviceClass: _joystickSummary?['cls'] as String?,
      peerModel: _joystickSummary?['model'] as String?,
      advisory: advisory,
    );
    if (_quality.value != next) {
      _quality.value = next;
      debugPrint(
        '[VR_HYBRID_HOST] ${jsonEncode({'transport': transport.name, 'hz': hz, 'peerModel': next.peerModel, 'advisory': advisory?.code})}',
      );
    }
  }

  @override
  void add(Object data) {
    if (!_open) return;
    _ble.add(data);
  }

  @override
  Future<void> close([int? code, String? reason]) async {
    if (!_open) return;
    _open = false;
    _udpWatchdog?.cancel();
    _udpWatchdog = null;
    _udpSocket?.close();
    _udpSocket = null;
    await _bleSub?.cancel();
    _bleSub = null;
    await _ble.close(code, reason);
    if (!_messages.isClosed) await _messages.close();
  }
}

class _PendingUdpEdge {
  _PendingUdpEdge({
    required this.sequence,
    required this.datagram,
    required this.nextRetryUs,
  });

  final int sequence;
  final Uint8List datagram;
  int nextRetryUs;
  int retries = 0;
}

/// Joystick-side wrapper around an authenticated BLE link. Probes offered LAN
/// endpoints via HMAC-SHA256 UDP pings, upgrades analog + button state traffic
/// to ~3 ms 5 GHz UDP automatically, and fails over instantaneously (< 320 ms)
/// to 1-packet BLE if Wi-Fi drops.
class VrHybridBleUdpClientLink
    implements VrObservableControllerLink, VrCompactGamepadCapableLink {
  VrHybridBleUdpClientLink({
    required VrControllerLink bleLink,
    required this.sessionToken,
    Map<String, Object?>? localCapabilitiesSummary,
    InternetAddress? bindAddress,
  }) : _ble = bleLink,
       _joystickSummary = localCapabilitiesSummary,
       _bindAddress = bindAddress ?? InternetAddress.anyIPv4 {
    _quality = ValueNotifier<VrControllerLinkQuality>(
      VrControllerLinkQuality(
        transport: _classifyBleTransport(_ble),
        canCarryVideoCast: false,
      ),
    );
    _messages = StreamController<Object?>(
      sync: true,
      onListen: _startListening,
      onPause: () => _bleSub?.pause(),
      onResume: () => _bleSub?.resume(),
      onCancel: () => unawaited(close()),
    );
  }

  static const _discreteIndices = [1, 2, 3, 8, 9, 10, 11];
  static const int _maxPendingEdges = 6;

  final VrControllerLink _ble;
  final String sessionToken;
  Map<String, Object?>? _joystickSummary;
  Map<String, Object?>? _visorSummary;
  final InternetAddress _bindAddress;
  late final StreamController<Object?> _messages;
  late final ValueNotifier<VrControllerLinkQuality> _quality;
  StreamSubscription<Object?>? _bleSub;

  RawDatagramSocket? _udpSocket;
  List<int>? _udpKey;
  List<InternetAddress> _candidateAddresses = const [];
  int _remoteUdpPort = 0;
  InternetAddress? _activeAddress;
  bool _udpActive = false;
  bool _peerSupportsCompactGamepad = false;
  double? _smoothedRttMs;
  int _pingSeq = 0;
  int _unansweredPingBursts = 0;
  int? _lastPongUs;
  Uint8List? _lastUdpDiscreteBytes;
  int? _lastCompactDiscreteSignature;
  String? _pendingBleFailoverSyncJson;
  final List<_PendingUdpEdge> _pendingEdges = <_PendingUdpEdge>[];
  Timer? _keepaliveTimer;
  Timer? _edgeRetransmitTimer;
  final Stopwatch _clock = Stopwatch()..start();
  bool _open = true;

  bool get isUdpActive => _udpActive;
  int get pendingDiscreteEdgeCount => _pendingEdges.length;

  @override
  bool get supportsCompactGamepadFrames =>
      _udpActive && _peerSupportsCompactGamepad;

  /// False for an older/non-negotiating BLE endpoint, including UDP upgrades.
  bool get pointerPostureEnabled =>
      _ble is VrBlePacketLink && _ble.pointerPostureEnabled;

  bool get _shoulderButtonsEnabled =>
      _ble is VrBlePacketLink && _ble.shoulderButtonsEnabled;
  double? get smoothedRttMs => _smoothedRttMs;

  @override
  bool get isOpen => _open && _ble.isOpen;

  @override
  Stream<Object?> get messages => _messages.stream;

  @override
  ValueListenable<VrControllerLinkQuality> get linkQualityListenable =>
      _quality;

  void _startListening() {
    if (_bleSub != null || !_open) return;
    _bleSub = _ble.messages.listen(
      _onBleMessage,
      onError: (Object error, StackTrace stack) {
        if (!_messages.isClosed) _messages.addError(error, stack);
      },
      onDone: () => unawaited(close()),
      cancelOnError: true,
    );
    unawaited(_sendPeerCapabilities());
  }

  Future<void> _sendPeerCapabilities() async {
    if (!_open) return;
    _joystickSummary ??= await VrBlePeerCapabilities.resolve();
    _recomputeQuality();
    if (!_open || !_ble.isOpen || _joystickSummary == null) return;
    try {
      _ble.add(
        jsonEncode({
          'type': VrHybridWireConstants.peerCapsType,
          'caps': _joystickSummary,
        }),
      );
    } catch (_) {}
  }

  void _onBleMessage(Object? data) {
    if (!_open || _messages.isClosed) return;
    if (data is String && data.length <= 2048) {
      try {
        final decoded = jsonDecode(data);
        if (decoded is Map<String, dynamic>) {
          final type = decoded['type'];
          if (type == VrHybridWireConstants.offerType) {
            unawaited(_acceptHybridOffer(decoded));
            return;
          }
          if (type == VrHybridWireConstants.linkAdviceType) {
            return;
          }
        }
      } catch (_) {}
    }
    _messages.add(data);
  }

  Future<void> _acceptHybridOffer(Map<String, dynamic> offer) async {
    if (!_open) return;
    final caps = offer['caps'];
    if (caps is Map) {
      _visorSummary = caps.cast<String, Object?>();
    }
    _peerSupportsCompactGamepad = offer['compactGamepadV1'] == true;
    final port = offer['udpPort'];
    final nonce = offer['nonce'];
    final rawIps = offer['ips'];
    if (port is! int ||
        port <= 0 ||
        port > 65535 ||
        nonce is! String ||
        nonce.length < 16 ||
        nonce.length > 64 ||
        rawIps is! List) {
      _recomputeQuality();
      return;
    }
    final parsedAddresses = <InternetAddress>[];
    for (final rawIp in rawIps) {
      if (rawIp is String) {
        final parsed = InternetAddress.tryParse(rawIp);
        if (parsed != null && parsed.type == InternetAddressType.IPv4) {
          parsedAddresses.add(parsed);
        }
      }
    }
    if (parsedAddresses.isEmpty) {
      _recomputeQuality();
      return;
    }

    _udpKey = _deriveHybridUdpKey(sessionToken, nonce);
    _remoteUdpPort = port;
    _candidateAddresses = parsedAddresses;

    try {
      _udpSocket?.close();
      final socket = await RawDatagramSocket.bind(_bindAddress, 0);
      if (!_open) {
        socket.close();
        return;
      }
      _udpSocket = socket;
      socket.listen(_onUdpEvent, onError: (_) {});
      _recomputeQuality();
      _startProbeAndKeepaliveLoop();
    } catch (_) {
      _recomputeQuality();
    }
  }

  void _demoteUdpToBle() {
    if (!_udpActive) return;
    _udpActive = false;
    _activeAddress = null;
    _pendingEdges.clear();
    _edgeRetransmitTimer?.cancel();
    _edgeRetransmitTimer = null;
    _recomputeQuality();
    final syncJson = _pendingBleFailoverSyncJson;
    _pendingBleFailoverSyncJson = null;
    if (syncJson != null && _ble.isOpen) {
      try {
        _ble.add(syncJson);
      } catch (_) {}
    }
  }

  void _startProbeAndKeepaliveLoop() {
    _keepaliveTimer?.cancel();
    _unansweredPingBursts = 0;
    _sendPingBurst();
    Future<void>.delayed(const Duration(milliseconds: 45), () {
      if (_open && !_udpActive) _sendPingBurst();
    });
    Future<void>.delayed(const Duration(milliseconds: 110), () {
      if (_open && !_udpActive) _sendPingBurst();
    });
    var idleTick = 0;
    _keepaliveTimer = Timer.periodic(const Duration(milliseconds: 160), (_) {
      if (!_open) return;
      final nowUs = _clock.elapsedMicroseconds;
      if (_udpActive) {
        if (_lastPongUs != null && nowUs - _lastPongUs! > 320000) {
          // Fast seamless failover back to BLE + immediate discrete state sync!
          _demoteUdpToBle();
        }
        _sendPingBurst();
      } else {
        idleTick++;
        // Re-probe every ~2.4 s initially, backing off to ~14.4 s after 3
        // unanswered probe cycles on AP-isolated or asymmetric networks.
        final probePeriodTicks = _unansweredPingBursts >= 3 ? 90 : 15;
        if (idleTick >= probePeriodTicks) {
          idleTick = 0;
          _unansweredPingBursts++;
          _sendPingBurst();
        }
      }
    });
  }

  void _sendPingBurst() {
    final socket = _udpSocket;
    final key = _udpKey;
    if (socket == null ||
        key == null ||
        _remoteUdpPort <= 0 ||
        _candidateAddresses.isEmpty) {
      return;
    }
    final seq = ++_pingSeq;
    final nowUs = _clock.elapsedMicroseconds;
    final body = Uint8List(17)
      ..[0] = 0x56
      ..[1] = 0x52
      ..[2] = 0x55
      ..[3] = 0x31
      ..[4] = VrHybridWireConstants.pingKind;
    final bd = ByteData.sublistView(body);
    bd.setUint32(5, seq, Endian.little);
    bd.setUint64(9, nowUs, Endian.little);
    final tag = _computeTag(key, body);
    final packet = Uint8List(VrHybridWireConstants.pingPongPacketBytes)
      ..setRange(0, 17, body)
      ..setRange(17, 33, tag);

    final targets = _activeAddress != null
        ? <InternetAddress>[_activeAddress!]
        : _candidateAddresses;
    for (final addr in targets) {
      try {
        socket.send(packet, addr, _remoteUdpPort);
      } catch (_) {}
    }
  }

  void _onUdpEvent(RawSocketEvent event) {
    if (!_open || event != RawSocketEvent.read) return;
    final socket = _udpSocket;
    final key = _udpKey;
    if (socket == null || key == null) return;
    Datagram? dg;
    while ((dg = socket.receive()) != null) {
      final data = dg!.data;
      if (!_hasMagic(data)) continue;
      final kind = data[4];
      if (kind == VrHybridWireConstants.stateAckKind &&
          data.length == VrHybridWireConstants.stateAckDatagramBytes) {
        if (!_verifyTagConstantTime(key, data, 9)) continue;
        final ackSeq = ByteData.sublistView(data).getUint32(5, Endian.little);
        _lastPongUs = _clock.elapsedMicroseconds;
        _pendingEdges.removeWhere(
          (e) => _isSequenceAtLeast32(ackSeq, e.sequence),
        );
        if (_pendingEdges.isEmpty) {
          _edgeRetransmitTimer?.cancel();
          _edgeRetransmitTimer = null;
          _pendingBleFailoverSyncJson = null;
        }
        continue;
      }
      if (kind != VrHybridWireConstants.pongKind ||
          data.length != VrHybridWireConstants.pingPongPacketBytes) {
        continue;
      }
      if (!_verifyTagConstantTime(key, data, 17)) continue;
      final bd = ByteData.sublistView(data);
      final sentUs = bd.getUint64(9, Endian.little);
      final nowUs = _clock.elapsedMicroseconds;
      if (nowUs < sentUs) continue;
      final rttMs = (nowUs - sentUs) / 1000.0;
      if (rttMs > 60.0) continue; // Keep BLE if Wi-Fi is severely congested.
      _lastPongUs = nowUs;
      _unansweredPingBursts = 0;
      _smoothedRttMs = _smoothedRttMs == null
          ? rttMs
          : (_smoothedRttMs! * 0.7 + rttMs * 0.3);
      final changed = !_udpActive || _activeAddress != dg.address;
      _activeAddress = dg.address;
      _udpActive = true;
      if (changed || (_quality.value.rttMs == null)) {
        _recomputeQuality();
      } else if ((_smoothedRttMs! - (_quality.value.rttMs ?? 0)).abs() >= 1.5) {
        _recomputeQuality();
      }
    }
  }

  void _recomputeQuality() {
    if (!_open) return;
    final transport = _udpActive
        ? _classifyUdpTransport(_visorSummary, _joystickSummary)
        : _classifyBleTransport(_ble);
    final hz = _negotiatedControllerHz(
      transport: transport,
      visorSummary: _visorSummary,
      joystickSummary: _joystickSummary,
    );
    final rtt = _udpActive ? _smoothedRttMs : null;
    final oneWay = rtt != null ? (rtt * 0.5).clamp(1.0, 50.0) : null;
    final advisory = VrLinkPerformanceAdvisor.evaluate(
      transport: transport,
      visorSummary: _visorSummary,
      joystickSummary: _joystickSummary,
    );
    final next = VrControllerLinkQuality(
      transport: transport,
      rttMs: rtt,
      oneWayEstimateMs: oneWay,
      recommendedHz: hz,
      canCarryVideoCast: _udpActive,
      peerSupportsMotion: _visorSummary?['gyro'] != false,
      peerSupportsConcurrentCameras: _visorSummary?['cam3'] == true,
      peerDeviceClass: _visorSummary?['cls'] as String?,
      peerModel: _visorSummary?['model'] as String?,
      advisory: advisory,
    );
    if (_quality.value != next) {
      _quality.value = next;
      debugPrint(
        '[VR_HYBRID_CLIENT] ${jsonEncode({'transport': transport.name, 'rttMs': rtt == null ? null : (rtt * 100).round() / 100, 'oneWayMs': oneWay == null ? null : (oneWay * 100).round() / 100, 'hz': hz, 'advisory': advisory?.code})}',
      );
    }
  }

  bool _isDiscreteEdge(Uint8List statePacket) {
    final prev = _lastUdpDiscreteBytes;
    if (prev == null) return true;
    for (var i = 0; i < _discreteIndices.length; i++) {
      if (statePacket[_discreteIndices[i]] != prev[i]) return true;
    }
    return false;
  }

  void _recordDiscrete(Uint8List statePacket) {
    final snap = _lastUdpDiscreteBytes ??= Uint8List(_discreteIndices.length);
    for (var i = 0; i < _discreteIndices.length; i++) {
      snap[i] = statePacket[_discreteIndices[i]];
    }
  }

  static int _compactDiscreteSignature(VrCompactGamepadFrame f) {
    var mask = f.modeIndex & 0x07;
    if (f.trigger) mask |= 1 << 3;
    if (f.action) mask |= 1 << 4;
    if (f.btnA) mask |= 1 << 5;
    if (f.btnB) mask |= 1 << 6;
    if (f.btnX) mask |= 1 << 7;
    if (f.btnY) mask |= 1 << 8;
    if (f.btnL) mask |= 1 << 9;
    if (f.btnR) mask |= 1 << 10;
    if (f.btnZL) mask |= 1 << 11;
    if (f.btnZR) mask |= 1 << 12;
    if (f.btnGrip) mask |= 1 << 13;
    if (f.stickClick) mask |= 1 << 14;
    if (f.recenter) mask |= 1 << 15;
    if (f.moveAtEdge) mask |= 1 << 16;
    if (f.laserSlideActive) mask |= 1 << 17;
    if (f.pointerPoseReady) mask |= 1 << 18;
    if (f.drivingPaused) mask |= 1 << 19;
    if (f.passthroughActive) mask |= 1 << 20;
    if (f.spatialHudVisible) mask |= 1 << 21;
    return mask ^ ((f.hostModeRevision ?? -1) << 22);
  }

  static String _compactToBleFallbackJson(VrCompactGamepadFrame f) {
    final modeName = switch (f.modeIndex) {
      1 => 'laser',
      2 => 'driving',
      3 => 'nes',
      _ => 'joystick',
    };
    return jsonEncode(<String, Object?>{
      'sequence': f.sequence,
      'mode': modeName,
      if (f.hostModeRevision != null) 'hostModeRevision': f.hostModeRevision,
      'stickX': f.stickX,
      'stickY': f.stickY,
      'lookX': f.lookX,
      'lookY': f.lookY,
      'laserX': f.laserX,
      'laserY': f.laserY,
      'steering': f.steering,
      'drivingTilt': f.drivingTilt,
      'throttle': f.throttle,
      'brake': f.brake,
      'trigger': f.trigger,
      'action': f.action,
      'btnA': f.btnA,
      'btnB': f.btnB,
      'btnX': f.btnX,
      'btnY': f.btnY,
      'btnL': f.btnL,
      'btnR': f.btnR,
      'btnZL': f.btnZL,
      'btnZR': f.btnZR,
      'btnGrip': f.btnGrip,
      'stickClick': f.stickClick,
      'recenter': f.recenter,
      'moveAtEdge': f.moveAtEdge,
      'laserSlideActive': f.laserSlideActive,
      'pointerPoseReady': f.pointerPoseReady,
      'controllerVisible': f.controllerVisible,
      'drivingPaused': f.drivingPaused,
      'motionAvailable': f.motionAvailable,
    });
  }

  void _enqueueEdgeRetry(int sequence, Uint8List datagram) {
    if (_pendingEdges.length >= _maxPendingEdges) {
      _pendingEdges.removeAt(0);
    }
    _pendingEdges.add(
      _PendingUdpEdge(
        sequence: sequence & 0xFFFFFFFF,
        datagram: datagram,
        nextRetryUs: _clock.elapsedMicroseconds + 4500,
      ),
    );
    _ensureEdgeRetryTimer();
  }

  void _ensureEdgeRetryTimer() {
    if (_edgeRetransmitTimer != null || !_open || _pendingEdges.isEmpty) return;
    _edgeRetransmitTimer = Timer.periodic(const Duration(milliseconds: 4), (
      timer,
    ) {
      if (!_open ||
          !_udpActive ||
          _udpSocket == null ||
          _activeAddress == null ||
          _pendingEdges.isEmpty) {
        timer.cancel();
        _edgeRetransmitTimer = null;
        return;
      }
      final nowUs = _clock.elapsedMicroseconds;
      for (var i = _pendingEdges.length - 1; i >= 0; i--) {
        final entry = _pendingEdges[i];
        if (nowUs < entry.nextRetryUs) continue;
        try {
          _udpSocket!.send(entry.datagram, _activeAddress!, _remoteUdpPort);
        } catch (_) {}
        entry.retries++;
        if (entry.retries >= 2) {
          _pendingEdges.removeAt(i);
        } else {
          entry.nextRetryUs = nowUs + 11000;
        }
      }
      if (_pendingEdges.isEmpty) {
        timer.cancel();
        _edgeRetransmitTimer = null;
      }
    });
  }

  bool _trySendCompactOverUdp(VrCompactGamepadFrame frame) {
    final socket = _udpSocket;
    final key = _udpKey;
    final target = _activeAddress;
    if (!_udpActive ||
        !_peerSupportsCompactGamepad ||
        socket == null ||
        key == null ||
        target == null ||
        _remoteUdpPort <= 0) {
      return false;
    }
    final encoded = const VrCompactGamepadCodec().encode(frame);
    final body = Uint8List(51)
      ..[0] = 0x56
      ..[1] = 0x52
      ..[2] = 0x55
      ..[3] = 0x31
      ..[4] = VrHybridWireConstants.compactGamepadKind
      ..setRange(5, 51, encoded);
    final tag = _computeTag(key, body);
    final datagram = Uint8List(
      VrHybridWireConstants.compactGamepadDatagramBytes,
    )
      ..setRange(0, 51, body)
      ..setRange(51, 67, tag);

    final sig = _compactDiscreteSignature(frame);
    final edge = _lastCompactDiscreteSignature != sig;
    final written = socket.send(datagram, target, _remoteUdpPort);
    if (written <= 0) return false;
    if (edge) {
      _lastCompactDiscreteSignature = sig;
      _pendingBleFailoverSyncJson = _compactToBleFallbackJson(frame);
      _enqueueEdgeRetry(frame.sequence, datagram);
    }
    return true;
  }

  bool _trySendStateOverUdp(String json) {
    final socket = _udpSocket;
    final key = _udpKey;
    final target = _activeAddress;
    if (!_udpActive ||
        socket == null ||
        key == null ||
        target == null ||
        _remoteUdpPort <= 0) {
      return false;
    }
    final allowEdge = _ble is! VrBlePacketLink || _ble.edgeTurnIntentEnabled;
    final encoded = VrBleWireCodec.encode(
      json,
      allowEdgeTurnIntent: allowEdge,
      allowPointerPosture: pointerPostureEnabled,
      allowShoulderButtons: _shoulderButtonsEnabled,
    );
    if (encoded.isEmpty ||
        encoded[0] != 1 ||
        encoded.length != VrBleWireCodec.statePacketBytes) {
      // Control packet (tag == 2): keep on reliable BLE!
      return false;
    }
    final seq = ByteData.sublistView(encoded).getUint32(4, Endian.little);
    final body = Uint8List(27)
      ..[0] = 0x56
      ..[1] = 0x52
      ..[2] = 0x55
      ..[3] = 0x31
      ..[4] = VrHybridWireConstants.stateKind
      ..[5] = allowEdge ? 1 : 0
      ..setRange(6, 27, encoded);
    final tag = _computeTag(key, body);
    final datagram = Uint8List(VrHybridWireConstants.stateDatagramBytes)
      ..setRange(0, 27, body)
      ..setRange(27, 43, tag);

    final edge = _isDiscreteEdge(encoded);
    final written = socket.send(datagram, target, _remoteUdpPort);
    if (written <= 0) return false;
    if (edge) {
      _recordDiscrete(encoded);
      _pendingBleFailoverSyncJson = json;
      _enqueueEdgeRetry(seq, datagram);
    }
    return true;
  }

  @override
  void add(Object data) {
    if (!_open) return;
    if (data is VrCompactGamepadFrame) {
      if (_trySendCompactOverUdp(data)) return;
      _pendingBleFailoverSyncJson = null;
      _ble.add(_compactToBleFallbackJson(data));
      return;
    }
    if (data is String && _udpActive) {
      try {
        if (_trySendStateOverUdp(data)) return;
      } catch (_) {
        // Malformed payload falls through to _ble.add for canonical handling.
      }
    }
    _pendingBleFailoverSyncJson = null;
    _ble.add(data);
  }

  @override
  Future<void> close([int? code, String? reason]) async {
    if (!_open) return;
    _open = false;
    _udpActive = false;
    _pendingEdges.clear();
    _pendingBleFailoverSyncJson = null;
    _keepaliveTimer?.cancel();
    _keepaliveTimer = null;
    _edgeRetransmitTimer?.cancel();
    _edgeRetransmitTimer = null;
    _udpSocket?.close();
    _udpSocket = null;
    await _bleSub?.cancel();
    _bleSub = null;
    await _ble.close(code, reason);
    if (!_messages.isClosed) await _messages.close();
  }
}
