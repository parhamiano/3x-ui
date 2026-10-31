import { z } from 'zod';

import { TrojanClientSchema } from './trojan';

// AnyTLS authenticates exactly like Trojan (one password per client).
export const AnyTLSClientSchema = TrojanClientSchema;
export type AnyTLSClient = z.infer<typeof AnyTLSClientSchema>;

export const AnyTLSInboundSettingsSchema = z.object({
  certificate: z.string().default(''),
  private_key: z.string().default(''),
  sni: z.string().default(''),
  padding_scheme: z.array(z.string()).optional(),
  clients: z.array(AnyTLSClientSchema).default([]),
});
export type AnyTLSInboundSettings = z.infer<typeof AnyTLSInboundSettingsSchema>;
