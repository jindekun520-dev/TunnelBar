// Package constraints 是 golang.org/x/exp/constraints 的最小本地副本。
//
// gvisor 的 pkg/bits 需要其中的类型约束；该包只有几十行，为避免引入
// 整个 x/exp 模块，这里直接内联一份等价定义。
package constraints

// Signed 是有符号整数类型集合。
type Signed interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

// Unsigned 是无符号整数类型集合。
type Unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// Integer 是整数类型集合。
type Integer interface {
	Signed | Unsigned
}

// Float 是浮点类型集合。
type Float interface {
	~float32 | ~float64
}

// Complex 是复数类型集合。
type Complex interface {
	~complex64 | ~complex128
}

// Ordered 是可比较大小的类型集合。
type Ordered interface {
	Integer | Float | ~string
}
