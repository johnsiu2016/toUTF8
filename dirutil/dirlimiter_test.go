package dirutil

import (
	"testing"
)

func Test_createOutputPath_1(t *testing.T) {
	outdir := "test_utf8"
	inpath := "test/abc.txt"

	expect := "test_utf8/abc.txt"
	actual := evaluateOutputPath(outdir, inpath)

	if expect != actual {
		t.Error()
	}
}

func Test_createOutputPath_2(t *testing.T) {
	outdir := "test_utf8"
	inpath := "test/sub/abc.txt"

	expect := "test_utf8/sub/abc.txt"
	actual := evaluateOutputPath(outdir, inpath)

	if expect != actual {
		t.Error()
	}
}

func Benchmark_createOutputPath(b *testing.B) {
	outdir := "test_utf8"
	inpath := "test/sub/abc.txt"
	for i := 0; i < b.N; i++ {
		evaluateOutputPath(outdir, inpath)
	}
}
