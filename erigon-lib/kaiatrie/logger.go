// Copyright 2025 The Kaia Authors
//
// Erigon is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Erigon is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Erigon. If not, see <http://www.gnu.org/licenses/>.

package kaiatrie

import "github.com/erigontech/erigon-lib/log/v3"

var (
	_ foreignLogger = (log.Logger)(nil)
	_ log.Handler   = (*foreignHandler)(nil)
)

// A minimal logger interface that might be supplied by foreign code.
type foreignLogger interface {
	Trace(msg string, ctx ...interface{})
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Warn(msg string, ctx ...interface{})
	Error(msg string, ctx ...interface{})
	Crit(msg string, ctx ...interface{})
}

type foreignHandler struct {
	l foreignLogger
}

func (h foreignHandler) Log(r *log.Record) error {
	switch r.Lvl {
	case log.LvlTrace:
		h.l.Trace(r.Msg, r.Ctx...)
	case log.LvlDebug:
		h.l.Debug(r.Msg, r.Ctx...)
	case log.LvlInfo:
		h.l.Info(r.Msg, r.Ctx...)
	case log.LvlWarn:
		h.l.Warn(r.Msg, r.Ctx...)
	case log.LvlError:
		h.l.Error(r.Msg, r.Ctx...)
	case log.LvlCrit:
		h.l.Crit(r.Msg, r.Ctx...)
	}
	return nil
}

func loggerFromForeign(l foreignLogger) log.Logger {
	logger := log.New()
	logger.SetHandler(foreignHandler{l})
	return logger
}
