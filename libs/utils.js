
function writeVarInt(value) {
  if (value < 0x40) {
    // 1 byte, prefix 00
    return new Uint8Array([value]); // אין צורך ב־& 0x3f
  }

  if (value < 0x4000) {
    // 2 bytes, prefix 01
    return new Uint8Array([
      0x40 | (value >> 8),
      value & 0xff
    ]);
  }

  if (value < 0x40000000) {
    // 4 bytes, prefix 10
    return new Uint8Array([
      0x80 | (value >> 24),
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff
    ]);
  }

  if (value <= Number.MAX_SAFE_INTEGER) {
    var hi = Math.floor(value / 2 ** 32);
    var lo = value >>> 0;
    return new Uint8Array([
      0xC0 | (hi >> 24),
      (hi >> 16) & 0xff,
      (hi >> 8) & 0xff,
      hi & 0xff,
      (lo >> 24) & 0xff,
      (lo >> 16) & 0xff,
      (lo >> 8) & 0xff,
      lo & 0xff
    ]);
  }

  throw new Error("Value too large for QUIC VarInt");
}


function writeVarInt2(value) {
  if (value < 0x40) {
    // 1 byte
    return new Uint8Array([value & 0x3f]);
  }

  if (value < 0x4000) {
    // 2 bytes
    return new Uint8Array([
      0x40 | ((value >> 8) & 0x3f),
      value & 0xff
    ]);
  }

  if (value < 0x40000000) {
    // 4 bytes
    return new Uint8Array([
      0x80 | ((value >> 24) & 0x3f),
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff
    ]);
  }

  if (value <= Number.MAX_SAFE_INTEGER) {
    var hi = Math.floor(value / 2 ** 32);
    var lo = value >>> 0;
    return new Uint8Array([
      0xC0 | ((hi >> 24) & 0x3f),
      (hi >> 16) & 0xff,
      (hi >> 8) & 0xff,
      hi & 0xff,
      (lo >> 24) & 0xff,
      (lo >> 16) & 0xff,
      (lo >> 8) & 0xff,
      lo & 0xff
    ]);
  }

  throw new Error("Value too large for QUIC VarInt");
}



function readVarInt(array, offset) {
  if (offset >= array.length) return null;

  var first = array[offset];
  var prefix = first >> 6;

  if (prefix === 0b00) {
    return {
      value: first & 0x3f,
      byteLength: 1
    };
  }

  if (prefix === 0b01) {
    if (offset + 1 >= array.length) return null;
    var value = ((first & 0x3f) << 8) | array[offset + 1];
    return {
      value,
      byteLength: 2
    };
  }

  if (prefix === 0b10) {
    if (offset + 3 >= array.length) return null;
    var value = (
      ((first & 0x3F) << 24) |
      (array[offset + 1] << 16) |
      (array[offset + 2] << 8) |
      array[offset + 3]
    ) >>> 0;
    return {
      value,
      byteLength: 4
    };
  }

  if (prefix === 0b11) {
    if (offset + 7 >= array.length) return null;

    var hi = (
      ((first & 0x3F) << 24) |
      (array[offset + 1] << 16) |
      (array[offset + 2] << 8) |
      array[offset + 3]
    ) >>> 0;

    var lo = (
      (array[offset + 4] << 24) |
      (array[offset + 5] << 16) |
      (array[offset + 6] << 8) |
      array[offset + 7]
    ) >>> 0;

    var full = BigInt(hi) * 4294967296n + BigInt(lo); // 2^32

    if (full <= BigInt(Number.MAX_SAFE_INTEGER)) {
      return {
        value: Number(full),
        byteLength: 8
      };
    } else {
      return {
        value: full,
        byteLength: 8
      };
    }
  }

  return null;
}



function concatUint8Arrays(arrays) {
    var totalLength = 0;
    for (var i = 0; i < arrays.length; i++) {
        totalLength += arrays[i].length;
    }

    var result = new Uint8Array(totalLength);
    var offset = 0;

    for (var i = 0; i < arrays.length; i++) {
        result.set(arrays[i], offset);
        offset += arrays[i].length;
    }

    return result;
}
       
function arraybufferEqual(buf1, buf2) {
  //if (buf1 === buf2) {
  //return true;
  //}

  if (buf1.byteLength !== buf2.byteLength) {
  return false;
  }

  var view1 = new DataView(buf1);
  var view2 = new DataView(buf2);

  for (var i = 0; i < buf1.byteLength; i++) {
    if (view1.getUint8(i) !== view2.getUint8(i)) {
      return false;
    }
  }

  return true;
}



function buildAckFrameFromPackets(packets, ecnStats, ackDelay) {
  if (!packets || packets.length === 0) return null;

  var sorted = packets.slice().sort((a, b) => b - a);

  var ranges = [];
  var rangeStart = sorted[0];
  var rangeEnd = rangeStart;
  var lastPn = rangeStart;

  for (var i = 1; i < sorted.length; i++) {
    var pn = sorted[i];
    if (pn === lastPn - 1) {
      lastPn = pn;
    } else {
      ranges.push({ start: lastPn, end: rangeEnd });
      rangeEnd = pn;
      lastPn = pn;
    }
  }
  ranges.push({ start: lastPn, end: rangeEnd });

  var firstRange = ranges[0].end - ranges[0].start;
  var ackRanges = [];

  for (var i = 1; i < ranges.length; i++) {
    var gap = ranges[i - 1].start - ranges[i].end - 1;
    var length = ranges[i].end - ranges[i].start;
    ackRanges.push({ gap: gap, length: length });
  }

  var frame = {
    type: 'ack',
    largest: sorted[0],
    delay: ackDelay || 0,  // ← כאן מכניסים את ה־delay שחושב
    firstRange: firstRange,
    ranges: ackRanges
  };

  if (ecnStats) {
    frame.ecn = {
      ect0: ecnStats.ect0 || 0,
      ect1: ecnStats.ect1 || 0,
      ce: ecnStats.ce || 0
    };
  }

  return frame;
}

function build_ack_info_from_ranges(flatRanges, ecnStats, ackDelay) {
  if (!flatRanges || flatRanges.length === 0) return null;
  if (flatRanges.length % 2 !== 0) throw new Error("flatRanges must be in [from, to, ...] pairs");

  var ranges = [];
  for (var i = 0; i < flatRanges.length; i += 2) {
    var from = flatRanges[i];
    var to = flatRanges[i + 1];
    if (to < from) throw new Error("Range end must be >= start");
    ranges.push({ start: from, end: to });
  }

  // Sort ranges from highest to lowest end
  ranges.sort((a, b) => b.end - a.end);

  // Merge overlapping or adjacent ranges
  var merged = [ranges[0]];
  for (var i = 1; i < ranges.length; i++) {
    var last = merged[merged.length - 1];
    var curr = ranges[i];
    if (curr.end >= last.start - 1) {
      // Merge them
      last.start = Math.min(last.start, curr.start);
    } else {
      merged.push(curr);
    }
  }

  var largest = merged[0].end;
  var firstRange = largest - merged[0].start;
  var ackRanges = [];

  for (var i = 1; i < merged.length; i++) {
    var gap = merged[i - 1].start - merged[i].end - 1;
    var length = merged[i].end - merged[i].start;
    ackRanges.push({ gap: gap, length: length });
  }

  return {
    type: 'ack',
    largest: largest,
    delay: ackDelay || 0,
    firstRange: firstRange,
    ranges: ackRanges,
    ecn: ecnStats ? {
      ect0: ecnStats.ect0 || 0,
      ect1: ecnStats.ect1 || 0,
      ce: ecnStats.ce || 0
    } : null
  };
}


function build_ack_info_from_ranges2(flatRanges, ecnStats, ackDelay) {
  if (!flatRanges || flatRanges.length === 0) return null;
  if (flatRanges.length % 2 !== 0) throw new Error("flatRanges must be in [from, to, ...] pairs");

  // בניית טווחים מלאים
  var ranges = [];
  for (var i = 0; i < flatRanges.length; i += 2) {
    var from = flatRanges[i];
    var to = flatRanges[i + 1];
    if (to < from) throw new Error("Range end must be >= start");
    ranges.push({ start: from, end: to });
  }

  // ממיינים מהגדול לקטן לפי end
  ranges.sort(function (a, b) { return b.end - a.end; });

  // הסרת טווחים חופפים או לא חוקיים
  for (var i = 1; i < ranges.length; i++) {
    if (ranges[i].end >= ranges[i - 1].start) {
      throw new Error("Overlapping ranges are not allowed");
    }
  }

  // התחלת ack מהטווח הגבוה ביותר
  var largest = ranges[0].end;
  var firstRange = largest - ranges[0].start;

  var ackRanges = [];
  var runningEnd = ranges[0].start - 1;

  for (var i = 1; i < ranges.length; i++) {
    var gap = runningEnd - ranges[i].end - 1;
    var length = ranges[i].end - ranges[i].start;

    // בדיקה אם הבלוק הבא יגלוש מתחת ל־0
    var nextEnd = runningEnd - (gap + 1 + length);
    if (nextEnd < 0) {
      console.warn("Skipped range due to underflow risk:", ranges[i]);
      continue; // לא מוסיפים את הטווח הזה
    }

    ackRanges.push({ gap: gap, length: length });
    runningEnd = ranges[i].start - 1;
  }

  var frame = {
    type: 'ack',
    largest: largest,
    delay: ackDelay || 0,
    firstRange: firstRange,
    ranges: ackRanges,
    ecn: ecnStats ? {
      ect0: ecnStats.ect0 || 0,
      ect1: ecnStats.ect1 || 0,
      ce: ecnStats.ce || 0
    } : null
  };

  return frame;
}



function quic_acked_info_to_ranges(ackFrame) {
  var flatRanges = [];

  if (!ackFrame || ackFrame.type !== 'ack') return flatRanges;

  var largest = ackFrame.largest;
  var firstRange = ackFrame.firstRange;

  // טווח ראשון: [largest - firstRange, largest]
  var rangeEnd = largest;
  var rangeStart = rangeEnd - firstRange;
  flatRanges.push(rangeStart, rangeEnd);

  // נתחיל לבנות את שאר הטווחים לפי gap+length
  var ranges = ackFrame.ranges || [];
  for (var i = 0; i < ranges.length; i++) {
    var { gap, length } = ranges[i];

    // מעבר אחורה לפי gap
    rangeEnd = rangeStart - 1 - gap;
    rangeStart = rangeEnd - length;

    flatRanges.push(rangeStart, rangeEnd);
  }

  return flatRanges;
}


export {
  concatUint8Arrays,
  arraybufferEqual,
  readVarInt,
  writeVarInt,
  quic_acked_info_to_ranges,
  build_ack_info_from_ranges
};
