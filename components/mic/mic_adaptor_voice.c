/*
 * Copyright (C) 2019-2020 Alibaba Group Holding Limited
 */

#include <stdlib.h>
#include <aos/aos.h>
#include <yoc/mic.h>
#include <yoc/mic_port.h>
#include <voice.h>

#define TAG "mic_voice";

static mic_event_t mic_evt;

#define BACLFLOW_LEN 0//(1024 * 300)
typedef struct {
    int len;
    char data[BACLFLOW_LEN];
} backflow_t;

backflow_t backflow[3] = {0};
static void backflow_copy(int id, void *data, int len)
{
    backflow_t *b = &backflow[id];

    if (BACLFLOW_LEN == 0) {
        return;
    }

    if ((b->len + len) < BACLFLOW_LEN) {
        memcpy(b->data + b->len, data, len);
        b->len += len;
    }
}

static void backflow_reset(void)
{
    backflow[0].len = 0;
    backflow[1].len = 0;
    backflow[2].len = 0;
}

static void voice_event(void *priv, voice_evt_id_t evt_id, void *data, int len)
{
    char *p = data;
    int data_len = len;

    if (evt_id == VOICE_ASR_EVT) {
        evt_id = MIC_EVENT_SESSION_START;
        p = NULL;
    } else if (evt_id == VOICE_DATA_EVT) {
        voice_data_t *vdata = (voice_data_t *)data;

        p = vdata->data;
        data_len = vdata->len;
        evt_id = MIC_EVENT_PCM_DATA;

        if (vdata->type == VOICE_MIC_DATA) {
            backflow_copy(0, p, data_len);
            evt_id = MIC_EVENT_MIC_DATA;
        } else if (vdata->type == VOICE_REF_DATA) {
            backflow_copy(1, p, data_len);
            evt_id = MIC_EVENT_REF_DATA;
        } else if (vdata->type == VOICE_AEC_DATA) {
            backflow_copy(2, p, data_len);
            evt_id = MIC_EVENT_PCM_DATA;
        } else if (vdata->type == VOICE_VAD_DATA) {
            if (vdata->flag == 0) {
                evt_id = MIC_EVENT_VAD;
            } else {
                return;
            }
        }
    } else if (evt_id == VOICE_SILENCE_EVT) {
        evt_id = MIC_EVENT_SESSION_STOP;
    }

    mic_evt(priv, evt_id, p, data_len);
}

static int mic_adaptor_init(mic_t *mic, mic_event_t event)
{
    mic_evt = event;
    voice_t *v;

    v = voice_init(voice_event, mic);
    mic_set_privdata(v);

    return 0;
}

static int mic_adaptor_deinit(mic_t *mic)
{
    voice_t * v = (voice_t *)mic_get_privdata();

    voice_deinit(v);

    return 0;
}

static int mic_adaptor_pcm_data_control(mic_t *mic, int flag, int enable)
{
    voice_t * v = (voice_t *)mic_get_privdata();

    if (enable == 1) {
        backflow_reset();
    }

    voice_backflow_control(v, VOICE_AEC_DATA, enable == 0? 0 : 1);
    voice_backflow_control(v, VOICE_REF_DATA, enable == 0? 0 : 1);
    voice_backflow_control(v, VOICE_MIC_DATA, enable == 0? 0 : 1);
    // voice_backflow_control(v, VOICE_VAD_DATA, flag == 0? 0 : 1);

    return 0;
}

static int mic_adaptor_set_param(mic_t *mic, mic_param_t *param)
{
    voice_adpator_param_t *p = (voice_adpator_param_t*)param->priv;
    voice_t              * v = (voice_t *)mic_get_privdata();
    voice_pcm_param_t      pcm_p;
    voice_param_t v_p;

    pcm_p.access        = 0;
    pcm_p.channles      = param->channels;
    pcm_p.channles_sum  = param->channels;
    pcm_p.rate          = param->rate;
    pcm_p.sample_bits   = param->sample_bits;
    pcm_p.pcm_name      = p->pcm;
    voice_add_mic(v, &pcm_p);

    pcm_p.pcm_name      = "pcmC2";
    voice_add_ref(v, &pcm_p);

    v_p.cts_ms          = p->cts_ms;
    v_p.ipc_mode        = p->ipc_mode;
    voice_config(v, &v_p);

    // voice_start(v);

    return 0;
}

static int mic_adaptor_start(mic_t *mic)
{
    voice_t * v = (voice_t *)mic_get_privdata();

    voice_start(v);
    voice_backflow_control(v, VOICE_VAD_DATA, 1);
    return 0;
}

static int mic_adaptor_stop(mic_t *mic)
{
    voice_t * v = (voice_t *)mic_get_privdata();

    voice_stop(v);
    return 0;
}

int mic_adaptor_audio_control(mic_t *mic, int enable, int timeout)
{
    voice_t * v = (voice_t *)mic_get_privdata();

    if (enable) {
        voice_unmute(v);
    } else {
        voice_mute(v, timeout);
    }

    return 0;
}

static mic_ops_t voice_ops = {
    .init = mic_adaptor_init,
    .deinit = mic_adaptor_deinit,
    .start = mic_adaptor_start,
    .stop = mic_adaptor_stop,
    .pcm_data_control = mic_adaptor_pcm_data_control,
    .set_param = mic_adaptor_set_param,
    .audio_control = mic_adaptor_audio_control,
};

void voice_mic_register(void)
{
    mic_ops_register(&voice_ops);
}
