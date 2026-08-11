// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Copyright (C) 2026 Kristof Bach <crys@crys.hu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package repofs

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// mtimeMetadataKey is the object metadata key (X-Amz-Meta-Mtime on the wire,
// without the x-amz-meta- prefix the SDK adds) that rclone and s3cmd preserve
// a file's modification time under. S3's own LastModified is the time of the
// upload rather than of the content, which is no use to a mirror or to the
// by-hash retention clock.
const mtimeMetadataKey = "mtime"

// formatMtime renders a modification time the way rclone and s3cmd write it:
// Unix seconds, with a nanosecond fraction when there is one.
func formatMtime(t time.Time) string {
	seconds := strconv.FormatInt(t.Unix(), 10)
	if t.Nanosecond() == 0 {
		return seconds
	}

	// Zero padded to nanoseconds and then trimmed, so that the fraction reads
	// as a fraction rather than as a count of whatever unit it stopped at.
	fraction := strings.TrimRight(fmt.Sprintf("%09d", t.Nanosecond()), "0")

	return seconds + "." + fraction
}

// parseMtime reads a Unix timestamp of the form "seconds" or
// "seconds.fraction" (1481478242.702218729). The two parts are parsed as
// integers rather than as one float64, which would lose precision well before
// nanoseconds.
func parseMtime(raw string) (time.Time, bool) {
	whole, frac, hasFrac := strings.Cut(raw, ".")

	seconds, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}, false
	}

	if !hasFrac {
		return time.Unix(seconds, 0), true
	}

	if len(frac) > 9 {
		frac = frac[:9]
	} else {
		frac += strings.Repeat("0", 9-len(frac))
	}

	nanoseconds, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return time.Time{}, false
	}

	return time.Unix(seconds, nanoseconds), true
}
