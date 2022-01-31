package dakuaz

func Authorize(levels ...uint32) uint32 {
	r := uint32(0)
	for _, l := range levels {
		r |= l
	}
	return r
}

func IsAuthorized(d *Dakuaz, levels ...uint32) bool {
	for _, l := range levels {
		if d.Level&l != l {
			return false
		}
	}
	return true
}
