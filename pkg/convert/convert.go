package convert

type Ints interface {
	int | int8 | int16 | int32 | int64 | uint | uint8 | uint16 | uint32 | uint64 | uintptr | float32 | float64
}

func ConvertSlice[T1 Ints, T2 Ints](in []T1) (out []T2) {
	for _, v := range in {
		out = append(out, T2(v))
	}
	return out
}
