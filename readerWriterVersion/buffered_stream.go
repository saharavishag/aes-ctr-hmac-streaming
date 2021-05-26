package dump

import (
	"fmt"
	"io"

	"go.uber.org/zap"
)

// bufferedStream used to mediate between encryption/decryption and encoder/decoder
// uses a messaging system where all messages are of the same size(except maybe the last)
// the channel is used as a queue between writer and reader, to allow them to operate (somewhat) independently
type bufferedStream struct {
	inBuf  []byte      // input buffer (writer)
	outBuf []byte      // output buffer (reader)
	ch     chan []byte // channel for slice
	log    *zap.Logger
}

func newBS(log *zap.Logger) *bufferedStream {
	return &bufferedStream{
		ch:  make(chan []byte, 100),
		log: log,
	}
}

/***
saves buffer with capacity n where n is chunk size
gets write:
if b.size < (n - buffer.size) append to buffer and wait for next write
else append to buffer (n - buffer.size) bytes and send buffer as msg, clear it and:
while remaining msg.size >= n, fill buffer with n bytes and send as msg
append to (empty) buffer remainder of message if any
once last item has been written, it's up to the caller to call flush(),
in order to send what's left in buffer and close the channel
***/
func (bs *bufferedStream) Write(p []byte) (int, error) {
	bs.log.Debug(fmt.Sprintf("received a write of %v bytes", len(p)))
	n := 0
	capa := bufferSize - len(bs.inBuf)
	// we got at least one chunk we can send for encryption
	for len(p) >= capa {
		if err := bs.copyToBuf(p[:capa]); err != nil {
			return 0, err
		}
		msg := make([]byte, bufferSize)
		copy(msg, bs.inBuf)
		bs.ch <- msg            // send buffer to encryption
		p = p[capa:]            // reslice dropping sent
		n += capa               // this much written
		bs.inBuf = bs.inBuf[:0] // reset buffer for next message
		capa = bufferSize       // only relevant for first iteration, then constant
	}
	// if there's anything left in p, copy to buffer and return
	if err := bs.copyToBuf(p); err != nil {
		return 0, err
	}
	n += len(p)
	return n, nil
}

// Writer call
func (bs *bufferedStream) flush() {
	bs.ch <- bs.inBuf // not necessarily full bufferSize
	close(bs.ch)      // important as "done" signal as well
}

func (bs *bufferedStream) copyToBuf(b []byte) error {
	if len(bs.inBuf)+len(b) > bufferSize {
		return fmt.Errorf("size of slice too big. len(b): %v, remaining size: %v, bufferSize: %v",
			len(b), bufferSize-len(bs.inBuf), bufferSize)
	}
	bs.inBuf = append(bs.inBuf, b...)
	return nil
}

// copies from internal buffer into p exactly numToCp bytes
func (bs *bufferedStream) copyFromBuf(p []byte, numToCp int) error {
	if numToCp > len(p) || len(bs.outBuf) < numToCp {
		return fmt.Errorf("Too much to copy. numToCp: %v, len(p): %v, len(bs.buf): %v",
			numToCp, len(p), len(bs.outBuf))
	}

	n := copy(p, bs.outBuf[:numToCp])
	if n != numToCp {
		return fmt.Errorf("Unexpected number of bytes copied. expected: %v, actual: %v", numToCp, n)
	}
	bs.outBuf = bs.outBuf[numToCp:] // reslice to discard what's been read

	return nil
}

// reads into p min(len(p), buffer + messages in queue), waits in case buffer and queue empty
func (bs *bufferedStream) Read(p []byte) (int, error) {
	capa := len(p) // max write size
	if capa == 0 { // see Read interface doc
		return 0, nil
	}
	var ok bool
	if len(bs.outBuf) == 0 { // wait for new data
		bs.outBuf, ok = <-bs.ch
		if !ok { // no new data is coming from closed channel
			return 0, io.EOF
		}
	}

	// need to empty the buffer before we get new messages
	numToCp := min(len(bs.outBuf), capa)
	// copy to p[] numToCp bytes from bs.buf
	if err := bs.copyFromBuf(p, numToCp); err != nil {
		return 0, err
	}
	capa -= numToCp
	n := numToCp

	for capa > 0 {
		bs.outBuf, ok = <-bs.ch
		if !ok {
			return n, nil // channel closed, return how much was written till now, next Read will get EOF
		}
		numToCp = min(len(bs.outBuf), capa)
		if err := bs.copyFromBuf(p[n:], numToCp); err != nil {
			return n, err
		}
		capa -= numToCp
		n += numToCp
	}

	return n, nil
}

// called by reader. in case of read error this prevents deadlock
func (bs *bufferedStream) discardReader() {
	for range bs.ch {
	}
}

func min(n, m int) int {
	if n > m {
		return m
	}
	return n
}
