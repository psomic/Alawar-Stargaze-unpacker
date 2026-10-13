def gr_name_hash(name, symbol_size=1, encoding="ascii") -> int:
    # сырые байты имени: при symbol_size=2 используем utf-16-le
    if symbol_size == 2:
        encoding = "utf-16-le"
    raw = name.encode(encoding)

    size = len(raw)  # = len * symbol_size
    # при нечётном размере игра читает ещё один байт за концом строки;
    # в поле data_name это нулевой терминатор, поэтому дополняем нулём
    if size % 2:
        raw += b"\x00"

    acc = 0
    for i in range(0, len(raw), 2):
        word = raw[i] | (raw[i + 1] << 8)          # little-endian
        acc = (word + (acc >> 1) + ((acc & 1) << 15)) & 0xFFFF

    return acc or 1


if __name__ == "__main__":
    print(hex(gr_name_hash("fonts/font17_script.xml.bindump")))
