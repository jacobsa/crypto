package cmac

import "unsafe"

func xorBlock(dst, src, length unsafe.Pointer) {
	dstPtr := (*byte)(dst)
	srcPtr := (*byte)(src)
	n := int(uintptr(length))
	
	dstSlice := (*[1 << 30]byte)(unsafe.Pointer(dstPtr))[:n:n]
	srcSlice := (*[1 << 30]byte)(unsafe.Pointer(srcPtr))[:n:n]
	
	for i:= 0; i <= n-8; i += 8 {
		dstSlice[i] ^= srcSlice[i]
		dstSlice[i+1] ^= srcSlice[i+1]
		dstSlice[i+2] ^= srcSlice[i+2]
		dstSlice[i+3] ^= srcSlice[i+3]
		dstSlice[i+4] ^= srcSlice[i+4]
		dstSlice[i+5] ^= srcSlice[i+5]
		dstSlice[i+6] ^= srcSlice[i+6]
		dstSlice[i+7] ^= srcSlice[i+7]
	}
	
	for i:= 0; i < n; i++ {
		dstSlice[i] ^= srcSlice[i]
	}
}

