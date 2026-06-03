// Package redis provides a minimal RESP2 client sufficient for session
// persistence. It avoids adding github.com/redis/go-redis as a dependency
// by implementing only the three commands verifiably-go needs:
// SET key value EX ttl, GET key, DEL key.
//
// Connection URL format (VERIFIABLY_REDIS_URL):
//
//	redis://[:password@]host:port[/db]
//
// Default: redis://localhost:6379/0
package redis

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client is a minimal, thread-safe RESP2 client. Each operation acquires a
// connection from a small pool. Connections are re-created on error.
type Client struct {
	addr     string
	password string
	db       int

	mu    sync.Mutex
	conns []*conn
}

type conn struct {
	net.Conn
	br *bufio.Reader
}

// Dial creates a Client from a redis:// URL.
func Dial(rawURL string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("redis: parse URL: %w", err)
	}
	host := u.Host
	if host == "" {
		host = "localhost:6379"
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":6379"
	}
	var password string
	if u.User != nil {
		password, _ = u.User.Password()
	}
	db := 0
	if u.Path != "" && u.Path != "/" {
		db, _ = strconv.Atoi(strings.TrimPrefix(u.Path, "/"))
	}
	c := &Client{addr: host, password: password, db: db}
	// Pre-open one connection to validate credentials.
	if _, err := c.acquire(); err != nil {
		return nil, fmt.Errorf("redis: connect to %s: %w", host, err)
	}
	return c, nil
}

// Set sets key to value with an expiry of ttl seconds.
func (c *Client) Set(key string, value []byte, ttl time.Duration) error {
	conn, err := c.acquire()
	if err != nil {
		return err
	}
	secs := int(ttl.Seconds())
	if secs < 1 {
		secs = 1
	}
	_, err = sendRecv(conn, arrayCmd("SET", key, string(value), "EX", strconv.Itoa(secs)))
	c.release(conn, err)
	return err
}

// Get returns the value for key, or (nil, nil) if the key doesn't exist.
func (c *Client) Get(key string) ([]byte, error) {
	conn, err := c.acquire()
	if err != nil {
		return nil, err
	}
	val, err := sendRecv(conn, arrayCmd("GET", key))
	c.release(conn, err)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	return []byte(fmt.Sprintf("%v", val)), nil
}

// Del deletes one or more keys.
func (c *Client) Del(keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	conn, err := c.acquire()
	if err != nil {
		return err
	}
	args := append([]string{"DEL"}, keys...)
	_, err = sendRecv(conn, arrayCmd(args...))
	c.release(conn, err)
	return err
}

// Ping sends a PING and returns an error if the server doesn't respond.
func (c *Client) Ping() error {
	conn, err := c.acquire()
	if err != nil {
		return err
	}
	_, err = sendRecv(conn, arrayCmd("PING"))
	c.release(conn, err)
	return err
}

// acquire returns a pooled connection or dials a new one.
func (c *Client) acquire() (*conn, error) {
	c.mu.Lock()
	if len(c.conns) > 0 {
		cn := c.conns[len(c.conns)-1]
		c.conns = c.conns[:len(c.conns)-1]
		c.mu.Unlock()
		return cn, nil
	}
	c.mu.Unlock()
	return c.dial()
}

func (c *Client) release(cn *conn, err error) {
	if err != nil {
		_ = cn.Close()
		return
	}
	c.mu.Lock()
	if len(c.conns) < 8 {
		c.conns = append(c.conns, cn)
	} else {
		_ = cn.Close()
	}
	c.mu.Unlock()
}

func (c *Client) dial() (*conn, error) {
	nc, err := net.DialTimeout("tcp", c.addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	cn := &conn{Conn: nc, br: bufio.NewReader(nc)}
	if c.password != "" {
		if _, err := sendRecv(cn, arrayCmd("AUTH", c.password)); err != nil {
			_ = nc.Close()
			return nil, fmt.Errorf("AUTH: %w", err)
		}
	}
	if c.db != 0 {
		if _, err := sendRecv(cn, arrayCmd("SELECT", strconv.Itoa(c.db))); err != nil {
			_ = nc.Close()
			return nil, fmt.Errorf("SELECT: %w", err)
		}
	}
	return cn, nil
}

// arrayCmd serialises a command as a RESP array.
func arrayCmd(args ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return []byte(b.String())
}

// sendRecv writes cmd and reads one reply. Returns the Go value (string,
// int64, []byte, nil) and an error.
func sendRecv(cn *conn, cmd []byte) (any, error) {
	_ = cn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cn.Write(cmd); err != nil {
		return nil, err
	}
	return readReply(cn.br)
}

// readReply parses one RESP reply.
func readReply(r *bufio.Reader) (any, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, fmt.Errorf("redis: empty reply")
	}
	switch line[0] {
	case '+': // Simple string
		return line[1:], nil
	case '-': // Error
		return nil, fmt.Errorf("redis: %s", line[1:])
	case ':': // Integer
		n, err := strconv.ParseInt(line[1:], 10, 64)
		return n, err
	case '$': // Bulk string
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		if n == -1 {
			return nil, nil // nil bulk string
		}
		buf := make([]byte, n+2)
		if _, err := readFull(r, buf); err != nil {
			return nil, err
		}
		return buf[:n], nil
	case '*': // Array
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		if n == -1 {
			return nil, nil
		}
		arr := make([]any, n)
		for i := range arr {
			arr[i], err = readReply(r)
			if err != nil {
				return nil, err
			}
		}
		return arr, nil
	}
	return nil, fmt.Errorf("redis: unknown reply type %q", line[0])
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
