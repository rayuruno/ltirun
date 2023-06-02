package check

func ContainsAny[I comparable](a []I, is ...I) bool {
	for _, x := range a {
		for _, y := range is {
			if x == y {
				return true
			}
		}
	}

	return false
}

func ContainsAll[I comparable](a []I, is ...I) bool {
	c := 0
	for _, i := range is {
		for _, v := range a {
			if i == v {
				c++
				break
			}
		}
	}
	return c == len(is)
}
