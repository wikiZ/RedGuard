/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: MicsSlice.go
 * @Time: 2022/5/26 13:54
 **/

package lib

import (
	"math/rand"
	"time"
)

// MicsSlice Returns a random element of the specified array
// @param	origin	  []int16	Gets an array of values
// @param	count	  int		Gets the number of random elements
func MicsSlice(origin []uint16, count int) []uint16 {
	tmpOrigin := make([]uint16, len(origin))
	copy(tmpOrigin, origin)
	rand.Seed(time.Now().Unix())
	rand.Shuffle(len(tmpOrigin), func(i int, j int) {
		tmpOrigin[i], tmpOrigin[j] = tmpOrigin[j], tmpOrigin[i]
	})

	result := make([]uint16, 0, count)
	for index, value := range tmpOrigin {
		if index == count {
			break
		}
		result = append(result, value)
	}
	return result
}
