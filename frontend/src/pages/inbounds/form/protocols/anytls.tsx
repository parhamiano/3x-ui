import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AutoComplete, Button, Form, Input, Space, message } from 'antd';
import { CloudDownloadOutlined } from '@ant-design/icons';
import { useFormContext, useWatch } from 'react-hook-form';

import { FormField } from '@/components/form/rhf';
import { HttpUtil } from '@/utils';

export default function AnyTLSFields() {
  const { t } = useTranslation();
  const [messageApi, messageContextHolder] = message.useMessage();
  const { control, setValue } = useFormContext();
  const [loadingPanelCert, setLoadingPanelCert] = useState(false);
  const sni = ((useWatch({ control, name: 'settings.sni' }) ?? '') as string).trim();

  const setCertFromPanel = async () => {
    setLoadingPanelCert(true);
    try {
      const msg = await HttpUtil.post('/panel/api/setting/all', undefined, { silent: true });
      const obj = msg?.obj as { webCertFile?: string; webKeyFile?: string } | undefined;
      if (!msg?.success || (!obj?.webCertFile && !obj?.webKeyFile)) {
        messageApi.warning(msg?.msg || t('pages.inbounds.setDefaultCertEmpty'));
        return;
      }
      if (obj.webCertFile) setValue('settings.certificate', obj.webCertFile);
      if (obj.webKeyFile) setValue('settings.private_key', obj.webKeyFile);
      messageApi.success(t('pages.inbounds.setSuccess'));
    } catch {
      messageApi.error(t('somethingWentWrong'));
    } finally {
      setLoadingPanelCert(false);
    }
  };

  const certOptions = sni
    ? [{ value: `/root/cert/${sni}/fullchain.pem` }, { value: `/etc/letsencrypt/live/${sni}/fullchain.pem` }]
    : [{ value: '/root/cert.pem' }];
  const keyOptions = sni
    ? [{ value: `/root/cert/${sni}/privkey.pem` }, { value: `/etc/letsencrypt/live/${sni}/privkey.pem` }]
    : [{ value: '/root/privkey.pem' }];

  return (
    <>
      {messageContextHolder}
      <FormField
        name={['settings', 'sni']}
        label={t('pages.xray.tuic.sni')}
        tooltip={t('pages.xray.tuic.sniHint')}
      >
        <Input placeholder="example.com" />
      </FormField>
      <FormField name={['settings', 'certificate']} label={t('pages.inbounds.publicKey')}>
        <AutoComplete options={certOptions} placeholder="/root/cert.pem" />
      </FormField>
      <FormField name={['settings', 'private_key']} label={t('pages.inbounds.privatekey')}>
        <AutoComplete options={keyOptions} placeholder="/root/privkey.pem" />
      </FormField>
      <Form.Item label=" ">
        <Space wrap>
          <Button
            type="primary"
            icon={<CloudDownloadOutlined aria-hidden />}
            loading={loadingPanelCert}
            onClick={setCertFromPanel}
          >
            {t('pages.inbounds.setDefaultCert')}
          </Button>
        </Space>
      </Form.Item>
    </>
  );
}
