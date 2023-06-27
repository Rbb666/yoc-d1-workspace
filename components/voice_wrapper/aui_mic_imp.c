/*
 * Copyright (C) 2019-2020 Alibaba Group Holding Limited
 */

#include <yoc/mic.h>
#include <yoc/mic_port.h>
#include <aos/aos.h>
#include <aos/ringbuffer.h>
#include <stdarg.h>
#include <ulog/ulog.h>

#define TAG "voice_wrapper"

#define FRAME_SIZE ((16000 / 1000) * (16 / 8) * 20) /* 640 */
#define RINGBUFFER_SIZE (FRAME_SIZE * CONFIG_MIC_RINGBUF_RAME + 1) /* 20ms * 20 */

typedef struct {
    dev_ringbuf_t ring_buffer;
    char *recv_buf;
} audio_t;

struct __mic {
    uservice_t      *srv;
    utask_t         *task;
    int              source;
    void            *param;
    aui_mic_evt_t    cb;
    int              evt_cnt;
    uint8_t          rbuf[FRAME_SIZE];
    char            *recv_buf;
    dev_ringbuf_t    ring_buffer;
    audio_t          audio;
    mic_ops_t       *ops;
    void            *priv;
};

typedef enum {
    _START_CMD,
    _STOP_CMD,
    _SET_ASR_CMD,
    _SET_ACTIVE_CMD,
    _SET_PARAM_CMD,
    _MUTE_CMD,
    _UNMUTE_CMD,
    _EVENT_CMD,
    _DEINIT_CMD,

    MIC_END_CMD
} MIC_CMD;

typedef struct {
    int evt_id;
    union {
        void *ptr;
        int  ival;
    };
    int size;
} evt_param_t;

static mic_t g_mic;

static int audio_new(void)
{
    g_mic.audio.recv_buf = aos_malloc_check(RINGBUFFER_SIZE);

    ringbuffer_create(&g_mic.audio.ring_buffer, g_mic.audio.recv_buf, RINGBUFFER_SIZE);

    return 0;
}

static int audio_free(void)
{
    if (g_mic.audio.recv_buf) {
        aos_free(g_mic.audio.recv_buf);
        g_mic.audio.recv_buf = NULL;
    }

    return 0;
}

static int audio_is_variable(void)
{
    return (g_mic.audio.recv_buf == NULL) ? 0 : 1;
}

static int audio_write(void *data, int size)
{
    return ringbuffer_write(&g_mic.audio.ring_buffer, data, size);
}

static int audio_read(void *data, int size)
{
    return ringbuffer_read(&g_mic.audio.ring_buffer, data, size);
}

static void mic_event_hdl(void *priv, mic_event_id_t event_id, void *data, int size)
{
    mic_t *mic = (mic_t *)priv;
    evt_param_t param;
    int len;
    int audio_recv_flag = 0;

    aos_check_return(mic);

    memset(&param, 0, sizeof(param));
    param.evt_id = event_id;

    if (event_id == MIC_EVENT_SESSION_START) {
        if (data != NULL) {
            mic_kws_t *k = aos_zalloc_check(sizeof(mic_kws_t));
            memcpy(k, data, sizeof(mic_kws_t));
            param.ptr = k;
        }
    } else if (event_id == MIC_EVENT_SESSION_STOP) {
        // stop
    } else if (event_id == MIC_EVENT_PCM_DATA ) {
        audio_recv_flag = 1;

        if (audio_is_variable() == 0) {
            audio_new();
        }

        len = audio_write(data, size);
        if (len < size) {
            LOGE(TAG, "audio is full, len(%d), size(%d)", len, size);
        }

        if (mic->evt_cnt < 2) {//CONFIG_MIC_RINGBUF_RAME
            mic->evt_cnt ++;
        } else {
           LOGE(TAG, "mic->evt_cnt %d >= 2, audio_recv_flag %d", mic->evt_cnt, audio_recv_flag); 
        }
    }

    if (mic->evt_cnt < 2 || audio_recv_flag == 0) {
        uservice_call_async(mic->srv, _EVENT_CMD, &param, sizeof(param));
    }

}

static int _set_param(mic_t *mic, rpc_t *rpc)
{
    int count;
    void *p = rpc_get_buffer(rpc, &count);

    memcpy(&mic->param, p, count);
    if (mic->ops->set_param) {
        mic->ops->set_param(mic, p, count);
    }

    return 0;
}

// 设置方向焦点源，0-7， -1 为所有方向都一样，指定方向增强，抑制其他方向的声音
static int _set_active(mic_t *mic, rpc_t *rpc)
{
    int source = rpc_get_int(rpc);

    mic->source = source;
    return 0;
}

static int _event_hdl(mic_t *mic, rpc_t *rpc)
{
    evt_param_t *param = (evt_param_t *)rpc_get_buffer(rpc, NULL);

    switch (param->evt_id) {
    case MIC_EVENT_PCM_DATA:
        while (1) {
        // {
            int size = audio_read(mic->rbuf, FRAME_SIZE);
            if (size > 0) {
                if (mic->cb) {
                    mic->cb(mic->source, MIC_EVENT_PCM_DATA, mic->rbuf, size);
                }
            } else {
                break;
            }
        }
        break;

    case MIC_EVENT_SESSION_START:
        if(mic->cb) {
            mic->cb(mic->source, MIC_EVENT_SESSION_START, param->ptr, sizeof(mic_kws_t));
        }

        if (param->ptr) {
            aos_free(param->ptr);
        }
        break;

    case MIC_EVENT_SESSION_STOP:
        if(mic->cb) {
            mic->cb(mic->source, MIC_EVENT_SESSION_STOP, NULL, 0);
        }
        break;

    default:
        break;
    }

    mic->evt_cnt = 0;
    return 0;
}

static int _start(mic_t *mic, rpc_t *rpc)
{
    if (g_mic.ops->start) {
        g_mic.ops->start(&g_mic);
    }

    if (g_mic.ops->event_control) {
        g_mic.ops->event_control(mic, MIC_EVENT_ALL_FLAG);
    }

    return 0;
}

static int _stop(mic_t *mic, rpc_t *rpc)
{
    if (g_mic.ops->stop) {
        g_mic.ops->stop(&g_mic);
    }

    return 0;
}

static int mute(mic_t *mic, rpc_t *rpc)
{
    int timeout = rpc_get_int(rpc);

    if (g_mic.ops->audio_control) {
        g_mic.ops->audio_control(mic, 0, timeout);
    }

    return 0;
}

static int unmute(mic_t *mic, rpc_t *rpc)
{
    if (g_mic.ops->audio_control) {
        g_mic.ops->audio_control(mic, 1, AOS_WAIT_FOREVER);
    }

    return 0;
}

static int _deinit_hdl(mic_t *mic, rpc_t *rpc)
{
    if (g_mic.ops->deinit) {
        g_mic.ops->deinit(mic);
    }

    audio_free();

    return 0;
}

static const rpc_process_t c_mic_cmd_cb_table[] = {
    {_START_CMD,             (process_t)_start},
    {_STOP_CMD,              (process_t)_stop},
    {_SET_PARAM_CMD,         (process_t)_set_param},
    {_SET_ACTIVE_CMD,        (process_t)_set_active},
    {_MUTE_CMD,              (process_t)mute},
    {_UNMUTE_CMD,            (process_t)unmute},
    {_EVENT_CMD,             (process_t)_event_hdl},
    {_DEINIT_CMD,            (process_t)_deinit_hdl},
    {MIC_END_CMD,            (process_t)NULL},
};

int mic_process_rpc(void *context, rpc_t *rpc)
{
    return uservice_process(context, rpc, c_mic_cmd_cb_table);
}

int aui_mic_set_param(void *param, int size)
{
    int ret = -1;

    aos_check_return_einval(g_mic.srv);

    ret = uservice_call_async(g_mic.srv, _SET_PARAM_CMD, (void *)param, size);
    return ret;
}

int aui_mic_set_wake_enable(int en)
{
    int ret = -1;
    int param = en;

    aos_check_return_einval(g_mic.srv);

    ret = uservice_call_async(g_mic.srv, _SET_ASR_CMD, (void *)&param, sizeof(int));
    return ret;
}

int aui_mic_set_active(int source)
{
    int ret = -1;
    int param = source;

    aos_check_return_einval(g_mic.srv);

    ret = uservice_call_async(g_mic.srv, _SET_ACTIVE_CMD, (void *)&param, sizeof(int));
    return ret;
}

int aui_mic_control(mic_ctrl_cmd_t cmd, ...)
{
    int ret = 0;

    //FIXME: private for 5654, reconstruct needed by wc
    //aos_check_return_einval(cmd >= MIC_CTRL_START_PCM && cmd <= MIC_CTRL_DEBUG);
    aos_check_return_einval(g_mic.srv);
    va_list ap;
    mic_t *mic = &g_mic;

    va_start(ap, cmd);

    if (cmd == MIC_CTRL_START_PCM) {
        if (mic->ops->pcm_data_control) {
            mic->ops->pcm_data_control(mic, 1);
        }
    } else if (cmd == MIC_CTRL_STOP_PCM) {
        if (mic->ops->pcm_data_control) {
            mic->ops->pcm_data_control(mic, 0);
        }
    } else if (cmd == MIC_CTRL_DEBUG) {
        int level = va_arg(ap, int);

        if (mic->ops->debug_control) {
            mic->ops->debug_control(mic, level);
        }
    } else if (cmd == MIC_CTRL_START_SESSION) {
        int enable = va_arg(ap, int);
        int vad_flag = va_arg(ap, int);

        if (mic->ops->kws_wakeup) {
            mic->ops->kws_wakeup(mic, enable, vad_flag);
        }
    }

    va_end(ap);

    return ret;
}


int aui_mic_mute(int timeout)
{
    int ret = -1;

    aos_check_return_einval(g_mic.srv);

    ret = uservice_call_async(g_mic.srv, _MUTE_CMD, (void *)&timeout, sizeof(int));

    return ret;
}

int aui_mic_unmute(void)
{
    int ret = -1;

    aos_check_return_einval(g_mic.srv);

    ret = uservice_call_async(g_mic.srv, _UNMUTE_CMD, NULL, 0);

    return ret;
}

int aui_mic_init(utask_t *task, aui_mic_evt_t evt_cb)
{
    aos_check_return_einval(task);

    if (g_mic.srv != NULL || g_mic.ops == NULL) {
        return -1;
    }

    if (g_mic.ops->init && g_mic.ops->init(&g_mic, mic_event_hdl) < 0) {
        LOGE(TAG, "mic srv ops init failed");
        return -1;
    }

    if (audio_new() < 0) {
        if (g_mic.ops->deinit) {
            g_mic.ops->deinit(&g_mic);
        }
        return -1;
    }

    g_mic.task = task;

    g_mic.srv = uservice_new("mic", mic_process_rpc, &g_mic);
    aos_check_return_enomem(g_mic.srv);

    utask_add(task, g_mic.srv);

    g_mic.cb = evt_cb;

    return 0;
}

int aui_mic_deinit(void)
{
    aos_check_return_einval(g_mic.srv && g_mic.ops);

    uservice_call_sync(g_mic.srv, _DEINIT_CMD, NULL, NULL, 0);

    mic_t *mic=&g_mic;
    utask_remove(mic->task, mic->srv);
    uservice_destroy(mic->srv);
    aos_free(mic->recv_buf);
    memset(mic, 0x00, sizeof(mic_t));

    return 0;
}

int aui_mic_start(void)
{
    aos_check_return_einval(g_mic.srv && g_mic.ops);

    int ret = uservice_call_async(g_mic.srv, _START_CMD, NULL, 0);

    return ret;
}

int aui_mic_stop(void)
{
    aos_check_return_einval(g_mic.srv && g_mic.ops);

    int ret = uservice_call_async(g_mic.srv, _STOP_CMD, NULL, 0);

    return ret;

    return 0;
}

int mic_set_privdata(void *priv)
{
    aos_check_return_einval(priv);

    g_mic.priv = priv;
    return 0;
}

void *mic_get_privdata(void)
{
    return (g_mic.priv);
}

int mic_ops_register(mic_ops_t *ops)
{
    g_mic.ops = ops;

    return 0;
}
