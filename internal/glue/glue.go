// glue.go - Internal glue interfaces.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package glue implements the internal interfaces used to glue the
// various mailproxy components together.
package glue

import (
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/internal/authority"
)

// ProxyInternals gives submodules access to proxy internals.
type ProxyInternals interface {
	Config() *config.Config
	LogBackend() *log.Backend
	Authorities() *authority.Store
}
