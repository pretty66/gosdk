package cache

import (
	"sync"
	"time"
)

type Cache struct {
	sw   sync.RWMutex
	data map[string]body
}

type body struct {
	Val    string `json:"val"`
	Expire int64  `json:"expire"`
}

var _cacheInstance *Cache

/**
 * tic: 多久清除一次缓存
 */
func NewCache(isClear bool, tic int) *Cache {
	if _cacheInstance == nil {
		_cacheInstance = &Cache{data: make(map[string]body)}
		// 10分钟主动清理一次过期缓存
		if isClear && tic > 0 {
			go _cacheInstance.clearExpireKey(tic)
		}
	}
	return _cacheInstance
}

func Instance() *Cache {
	if _cacheInstance == nil {
		return NewCache(false, 0)
	}
	return _cacheInstance
}

func (this *Cache) Set(key, value string, expire int64) error {
	this.sw.Lock()
	defer this.sw.Unlock()

	var exp int64
	if expire <= 0 {
		exp = -1
	} else {
		exp = time.Now().Unix() + expire
	}
	this.data[key] = body{
		Val:    value,
		Expire: exp,
	}
	return nil
}

func (this *Cache) Get(key string) string {
	this.sw.RLock()
	defer this.sw.RUnlock()

	body, ok := this.data[key]

	if !ok {
		return ""
	}
	if body.Expire == -1 {
		return body.Val
	}
	now := time.Now().Unix()
	if now < body.Expire {
		return body.Val
	}
	go this.Delete(key)
	return ""
}

func (this *Cache) GetAll(limit int) map[string]map[string]string {
	this.sw.RLock()
	defer this.sw.RUnlock()
	now := time.Now().Unix()
	out := make(map[string]map[string]string)
	if limit <= 0 {
		limit = 200
	}

	for k, v := range this.data {
		if len(out) >= limit {
			break
		}
		expire := "0"
		if v.Expire > 0 {
			expire = time.Unix(v.Expire, 0).Format("2006-01-02 15:04:05")
		}
		if v.Expire == -1 {
			out[k] = map[string]string{
				"data":   v.Val,
				"expire": expire,
			}
			continue
		}
		if now < v.Expire {
			out[k] = map[string]string{
				"data":   v.Val,
				"expire": expire,
			}
			continue
		}
		go this.Delete(k)
	}
	return out
}

func (this *Cache) Clear() {
	this.sw.Lock()
	defer this.sw.Unlock()
	for k := range this.data {
		delete(this.data, k)
	}
}

func (this *Cache) Delete(key string) {
	this.sw.Lock()
	defer this.sw.Unlock()
	delete(this.data, key)
}

// 清除过期缓存
func (this *Cache) clearExpireKey(tic int) {
	ticker := time.NewTicker(time.Second * time.Duration(tic))
	for range ticker.C {
		now := time.Now().Unix()
		for key, val := range this.data {
			if val.Expire <= 0 {
				continue
			}
			if val.Expire < now {
				this.Delete(key)
			}
		}
	}
}
