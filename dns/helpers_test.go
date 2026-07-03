package dns

import (
	"fmt"
	"net"
)

func netIP() net.IP { return net.IPv4(93, 184, 216, 34) }

func fmtName(i int) string { return fmt.Sprintf("host%d.example.", i) }
