/*
	 Copyright (C) 2017 xiewenzhou(Joe)


	 This program is distributed in the hope that it will be useful,
         but WITHOUT ANY WARRANTY; without even the implied warranty of
	 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	 GNU General Public License for more details.

*/

#pragma once

#define EXPORT __attribute__ ((visibility ("default")))

EXPORT int kbz_event_get(int chan_id, void **out, int *out_len, int timeout);
EXPORT int kbz_event_post(int chan_id, void *in, int in_len);
EXPORT int kbz_event_push(int chan_id, void *in, int in_len, void **out, int *out_len, int timeout);
EXPORT int kbz_event_ack(void *in, void *out, int out_len);

