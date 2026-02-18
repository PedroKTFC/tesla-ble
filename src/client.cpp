// https://github.com/platformio/platform-espressif32/issues/957
// specifically set when compiling with ESP-IDF
#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif

#include <string>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
//#include <esphome/core/helpers.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha1.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <sstream>

//#include "helpers.h"
#include "car_server.pb.h"
#include "client.h"
#include "keys.pb.h"
#include "universal_message.pb.h"
#include "vcsec.pb.h"
#include "peer.h"
#include "vehicle.pb.h"
#include "tb_utils.h"
#include "errors.h"

namespace TeslaBLE
{
  void Client::setVIN(const char *vin)
  {
    this->VIN = vin;
  }

  static char format_hex_char(uint8_t v) { return v >= 10 ? 'a' + (v - 10) : '0' + v; }
  std::string format_hex(const uint8_t *data, size_t length) {
    std::string ret;
    ret.resize(length * 2);
    for (size_t i = 0; i < length; i++) {
      ret[2 * i] = format_hex_char((data[i] & 0xF0) >> 4);
      ret[2 * i + 1] = format_hex_char(data[i] & 0x0F);
    }
    return ret;
  }
  std::string format_hex(const std::vector<uint8_t> &data) { return format_hex(data.data(), data.size()); }

  void Client::setConnectionID(const pb_byte_t *connection_id)
  {
    memcpy(this->connectionID, connection_id, 16);
  }

  /*
   * This will create a new private key, public key
   * and generates the key_id
   *
   * @return int result code 0 for successful
   */
  int Client::createPrivateKey()
  {
    mbedtls_entropy_context entropy_context;
    mbedtls_entropy_init(&entropy_context);

    // Use existing shared pointers, don't create new ones
    mbedtls_pk_free(private_key_context_.get());
    mbedtls_pk_init(private_key_context_.get());

    mbedtls_ctr_drbg_free(drbg_context_.get());
    mbedtls_ctr_drbg_init(drbg_context_.get());

    int return_code = mbedtls_ctr_drbg_seed(drbg_context_.get(), mbedtls_entropy_func,
                                            &entropy_context, nullptr, 0);
    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    return_code = mbedtls_pk_setup(
        private_key_context_.get(),
        mbedtls_pk_info_from_type((mbedtls_pk_type_t)MBEDTLS_PK_ECKEY));

    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    return_code = mbedtls_ecp_gen_key(
        MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*private_key_context_.get()),
        mbedtls_ctr_drbg_random, drbg_context_.get());

    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    return this->generatePublicKey();
  }

  int Client::loadPrivateKey(const uint8_t *private_key_buffer,
                             size_t private_key_length)
  {
    mbedtls_entropy_context entropy_context;
    mbedtls_entropy_init(&entropy_context);

    // Use existing shared pointers, don't create new ones
    mbedtls_pk_free(private_key_context_.get());
    mbedtls_pk_init(private_key_context_.get());

    mbedtls_ctr_drbg_free(drbg_context_.get());
    mbedtls_ctr_drbg_init(drbg_context_.get());

    int return_code = mbedtls_ctr_drbg_seed(drbg_context_.get(), mbedtls_entropy_func,
                                            &entropy_context, nullptr, 0);
    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    pb_byte_t password[0];
    return_code = mbedtls_pk_parse_key(
        private_key_context_.get(), private_key_buffer, private_key_length,
        password, 0, mbedtls_ctr_drbg_random, drbg_context_.get());

    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    session_vcsec_->setPrivateKeyContext(private_key_context_);
    session_infotainment_->setPrivateKeyContext(private_key_context_);

    return this->generatePublicKey();
  }

  int Client::getPrivateKey(pb_byte_t *output_buffer, size_t output_buffer_length, size_t *output_length)
  {
    int return_code = mbedtls_pk_write_key_pem(private_key_context_.get(), output_buffer, output_buffer_length);
    if (return_code != 0)
    {
      LOG_ERROR("Failed to write private key");
      return 1;
    }
    *output_length = strlen((char *)output_buffer) + 1;
    return 0;
  }

  int Client::getPublicKey(pb_byte_t *output_buffer, size_t output_buffer_length)
  {
    if (this->public_key_size_ <= output_buffer_length)
    {
      memcpy(output_buffer, this->public_key_, this->public_key_size_);
      return this->public_key_size_;
    }
    return 0;
  }

  int Client::generatePublicKey()
  {
    int return_code = mbedtls_ecp_point_write_binary(
        &mbedtls_pk_ec(*private_key_context_.get())->private_grp,
        &mbedtls_pk_ec(*private_key_context_.get())->private_Q,
        MBEDTLS_ECP_PF_UNCOMPRESSED, &this->public_key_size_, this->public_key_,
        sizeof(this->public_key_));

    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }
    return this->GenerateKeyId();
  }

  int Client::GenerateKeyId()
  {
    pb_byte_t buffer[20];
    int return_code = mbedtls_sha1(this->public_key_, this->public_key_size_, buffer);
    if (return_code != 0)
    {
      LOG_ERROR("SHA1 KeyId hash error: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    // we only need the first 4 bytes
    memcpy(this->public_key_id_, buffer, 4);
    return 0;
  }
    /*
   * This inserts the size of the message into the first two bytes of the message
   *
   * @param input_buffer_length Size of the input buffer
   * @param output_buffer Pointer to the output buffer
   * @param output_length Pointer to size_t that will store the written length
   */
  void Client::insertLength (size_t input_buffer_length,
                             pb_byte_t *output_buffer,
                             size_t *output_length)
  {
    *output_buffer = input_buffer_length >> 8;
    *(output_buffer + 1) = input_buffer_length & 0xFF;
    *output_length = input_buffer_length + 2;
    if (*output_length > UniversalMessage_RoutableMessage_size) {
        LOG_ERROR ("[insertLength] Output length too long **********************: i", *output_length);
    }
  }

  /*
   * This prepends the size of the message to the
   * front of the message and copies the message to the output buffer
   *
   * @param input_buffer Pointer to the input buffer
   * @param input_buffer_length Size of the input buffer
   * @param output_buffer Pointer to the output buffer
   * @param output_length Pointer to size_t that will store the written length
   */
/*  void Client::prependLength(const pb_byte_t *input_buffer,
                             size_t input_buffer_length,
                             pb_byte_t *output_buffer,
                             size_t *output_buffer_length)
  {
    uint8_t higher_byte = input_buffer_length >> 8;
    uint8_t lower_byte = input_buffer_length & 0xFF;

    uint8_t temp_buffer[2];
    temp_buffer[0] = higher_byte;
    temp_buffer[1] = lower_byte;

    memcpy(output_buffer, temp_buffer, sizeof(temp_buffer));
    memcpy(output_buffer + 2, input_buffer, input_buffer_length);
    *output_buffer_length = input_buffer_length + 2;
  }
*/
  /*
   * This will build the message need to whitelist
   * the public key in the car.
   * Beware that the car does not show any signs of that
   * interaction before you tab your keyboard on the reader
   *
   * @param input_buffer Pointer to the input buffer
   * @param input_buffer_length Size of the input buffer
   * @param output_buffer Pointer to the output buffer
   * @param output_length Pointer to size_t that will store the written length
   * @return int result code 0 for successful
   */
  int Client::buildWhiteListMessage(Keys_Role role,
                                    VCSEC_KeyFormFactor form_factor,
                                    pb_byte_t *output_buffer,
                                    size_t *output_length)
  {
    // printf("Building whitelist message\n");
    if (!mbedtls_pk_can_do(this->private_key_context_.get(), MBEDTLS_PK_ECKEY))
    {
      LOG_ERROR("[buildWhiteListMessage] Private key is not initialized");
      return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
    }

    VCSEC_UnsignedMessage payload = VCSEC_UnsignedMessage_init_default;
    payload.which_sub_message     = VCSEC_UnsignedMessage_WhitelistOperation_tag;

    // Initialize WhitelistOperation before setting nested fields, otherwise
    // the init_default assignment overwrites the PermissionChange data.
    payload.sub_message.WhitelistOperation                              = VCSEC_WhitelistOperation_init_default;
    payload.sub_message.WhitelistOperation.has_metadataForKey           = true;
    payload.sub_message.WhitelistOperation.metadataForKey.keyFormFactor = form_factor;
    payload.sub_message.WhitelistOperation.which_sub_message            = VCSEC_WhitelistOperation_addKeyToWhitelistAndAddPermissions_tag;

    payload.sub_message.WhitelistOperation.sub_message.addKeyToWhitelistAndAddPermissions                       = VCSEC_PermissionChange_init_default;
    payload.sub_message.WhitelistOperation.sub_message.addKeyToWhitelistAndAddPermissions.has_key               = true;
    memcpy(payload.sub_message.WhitelistOperation.sub_message.addKeyToWhitelistAndAddPermissions.key.PublicKeyRaw.bytes, this->public_key_, this->public_key_size_);
    payload.sub_message.WhitelistOperation.sub_message.addKeyToWhitelistAndAddPermissions.key.PublicKeyRaw.size = this->public_key_size_;
    payload.sub_message.WhitelistOperation.sub_message.addKeyToWhitelistAndAddPermissions.keyRole               = role;

    // printf("Encoding whitelist message\n");
    pb_byte_t payload_buffer[VCSEC_UnsignedMessage_size];
    size_t payload_length;
    int return_code = pb_encode_fields(payload_buffer, &payload_length, VCSEC_UnsignedMessage_fields, &payload);
    if (return_code != 0)
    {
      LOG_ERROR("Failed to encode whitelist message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }

    // printf("Building VCSEC to VCSEC message\n");
    VCSEC_ToVCSECMessage vcsec_message                      = VCSEC_ToVCSECMessage_init_default;
    vcsec_message.signedMessage                             = VCSEC_SignedMessage_init_default;
    vcsec_message.has_signedMessage                         = true;
    vcsec_message.signedMessage.signatureType               = VCSEC_SignatureType_SIGNATURE_TYPE_PRESENT_KEY;
    memcpy(vcsec_message.signedMessage.protobufMessageAsBytes.bytes, &payload_buffer, payload_length);
    vcsec_message.signedMessage.protobufMessageAsBytes.size = payload_length;

    // printf("Encoding VCSEC to VCSEC message\n");
//    pb_byte_t vcsec_encode_buffer[VCSEC_ToVCSECMessage_size];
    size_t vcsec_encode_buffer_size;
    return_code = pb_encode_fields(output_buffer+(&output_buffer[2]-&output_buffer[0]), &vcsec_encode_buffer_size, VCSEC_ToVCSECMessage_fields, &vcsec_message);
    if (return_code != 0)
    {
      LOG_ERROR("[buildWhiteListMessage] Failed to encode VCSEC to VCSEC message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    this->insertLength(vcsec_encode_buffer_size, output_buffer, output_length);
    return 0;
  }

  /*
   * This will parse the incoming message
   *
   * @param input_buffer Pointer to the input buffer
   * @param input_buffer_length Size of the input buffer
   * @param output_message Pointer to the output message
   * @return int result code 0 for successful
   */
  int Client::parseFromVCSECMessage(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                    VCSEC_FromVCSECMessage *output_message)
  {
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status = pb_decode(&stream, VCSEC_FromVCSECMessage_fields, output_message);
    if (!status)
    {
      LOG_ERROR("[parseFromVCSECMessage] Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return 0;
  }

  int Client::parseVCSECInformationRequest(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                           VCSEC_InformationRequest *output)
  {
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status = pb_decode(&stream, VCSEC_InformationRequest_fields, output);
    if (!status)
    {
      LOG_ERROR("[parseVCSECInformationRequest] Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return 0;
  }

  /*
   * This will parse the incoming message
   *
   * @param input_buffer Pointer to the input buffer
   * @param input_buffer_length Size of the input buffer
   * @param output_message Pointer to the output message
   * @return int result code 0 for successful
   */

  int Client::parseUniversalMessage(pb_byte_t *input_buffer,
                                    size_t input_buffer_length,
                                    UniversalMessage_RoutableMessage *output)
  {
    LOG_ERROR ("[parseUniversalMessage] Entering at version 2026.2.1");
    pb_istream_t stream = pb_istream_from_buffer(input_buffer, input_buffer_length);
    bool status = pb_decode(&stream, UniversalMessage_RoutableMessage_fields, output);
    if (!status)
    {
      LOG_ERROR("[parseUniversalMessage] Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    // If the response includes a signature_data.AES_GCM_Response_data field, then the protobuf_message_as_bytes payload is encrypted. Otherwise, the payload is plaintext.
    // TODO

    return 0;
  }
  int Client::parseUniversalMessageBLE(pb_byte_t *input_buffer,
                                       size_t input_buffer_length,
                                       UniversalMessage_RoutableMessage *output)
  {
    if (input_buffer_length < 2)
    {
      LOG_ERROR("[parseUniversalMessageBLE] BLE Message too short");
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }
    return parseUniversalMessage(input_buffer + 2, input_buffer_length - 2, output);
  }

  int Client::parsePayloadSessionInfo(UniversalMessage_RoutableMessage_session_info_t *input_buffer,
                                      Signatures_SessionInfo *output)
  {
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status = pb_decode(&stream, Signatures_SessionInfo_fields, output);
    if (!status)
    {
      LOG_ERROR("[parsePayloadSessionInfo] Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return 0;
  }
/* Doesn't seem to be used
  int Client::parsePayloadUnsignedMessage(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                          VCSEC_UnsignedMessage *output)
  {
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status = pb_decode(&stream, VCSEC_UnsignedMessage_fields, output);
    if (!status)
    {
      LOG_ERROR("[parsePayloadUnsignedMessage] Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return 0;
  }
*/
  int Client::parsePayloadCarServerResponse(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                            Signatures_SignatureData *signature_data,
                                            pb_size_t which_sub_sigData,
                                            UniversalMessage_MessageFault_E signed_message_fault,
                                            CarServer_Response *output)
  {
    // If encrypted, decrypt the payload
    if (which_sub_sigData != 0)
    {
      switch (signature_data->which_sig_type)
      {
        case Signatures_SignatureData_AES_GCM_Response_data_tag:
        {
          LOG_DEBUG("AES_GCM_Response_data found in signature_data");
          auto session = this->getPeer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
          if (!session->isInitialized())
          {
            LOG_ERROR("Session not initialized");
            return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
          }
          ESP_LOGD (TAG, "Encrypted buffer contents: %s length = %d", format_hex(input_buffer->bytes, input_buffer->size).c_str(), input_buffer->size);
          UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t decrypt_buffer;
          size_t decrypt_length;
          int return_code = session->DecryptResponse(
              input_buffer->bytes,
              input_buffer->size,
              signature_data->sig_type.AES_GCM_Response_data.nonce,
              signature_data->sig_type.AES_GCM_Response_data.tag,
              this->last_request_hash_,
              this->last_request_hash_length_,
              UniversalMessage_Flags_FLAG_ENCRYPT_RESPONSE,
              signed_message_fault,
              decrypt_buffer.bytes,
              sizeof(decrypt_buffer.bytes),
              &decrypt_length);
          if (return_code != 0)
          {
            LOG_ERROR("[parsePayloadCarServerResponse] Failed to decrypt response");
            return TeslaBLE_Status_E_ERROR_DECRYPT;
          }

          // Set the size of the decrypted buffer
          decrypt_buffer.size = decrypt_length;
          ESP_LOGD (TAG, "Decrypted buffer contents: %s length = %d", format_hex(decrypt_buffer.bytes, decrypt_buffer.size).c_str(), decrypt_buffer.size);
          pb_istream_t stream = pb_istream_from_buffer(decrypt_buffer.bytes, decrypt_buffer.size);
          bool status = pb_decode(&stream, CarServer_Response_fields, output);
          if (!status)
          {
            LOG_ERROR("[parsePayloadCarServerResponse] Decoding failed: %s", PB_GET_ERROR(&stream));
            return TeslaBLE_Status_E_ERROR_PB_DECODING;
          }
          break;
        }
        default:
          LOG_DEBUG("No AES_GCM_Response_data found in signature_data");
          return TeslaBLE_Status_E_ERROR_DECRYPT;
      }
    }
    else
    {
      pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
      bool status = pb_decode(&stream, CarServer_Response_fields, output);
      if (!status)
      {
        LOG_ERROR("[parsePayloadCarServerResponse] Decoding failed: %s", PB_GET_ERROR(&stream));
        return TeslaBLE_Status_E_ERROR_PB_DECODING;
      }
    }

    return 0;
  }

  int Client::buildUniversalMessageWithPayload(pb_byte_t *payload,
                                               size_t payload_length,
                                               UniversalMessage_Domain domain,
                                               pb_byte_t *output_buffer,
                                               size_t *output_length,
                                               bool encryptPayload)
  {
    UniversalMessage_RoutableMessage universal_message = UniversalMessage_RoutableMessage_init_default;

    universal_message.to_destination = UniversalMessage_Destination_init_default;
    universal_message.to_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
    universal_message.to_destination.sub_destination.domain = domain;
    universal_message.has_to_destination = true;
/*
    UniversalMessage_Destination destination = UniversalMessage_Destination_init_default;
    destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
    destination.sub_destination.domain = domain;
    universal_message.has_to_destination = true;
    universal_message.to_destination = destination;
*/
    LOG_DEBUG("Building message for domain: %d", domain);
    auto session = this->getPeer(domain);

    session->incrementCounter();

    universal_message.from_destination = UniversalMessage_Destination_init_default;
    universal_message.from_destination.which_sub_destination = UniversalMessage_Destination_routing_address_tag;
    memcpy(universal_message.from_destination.sub_destination.routing_address.bytes, this->connectionID, sizeof(this->connectionID));
    universal_message.from_destination.sub_destination.routing_address.size = sizeof(this->connectionID);
    universal_message.has_from_destination = true;
/*
    destination = UniversalMessage_Destination_init_default;
    destination.which_sub_destination = UniversalMessage_Destination_routing_address_tag;
    memcpy(destination.sub_destination.routing_address.bytes, this->connectionID, sizeof(this->connectionID));
    destination.sub_destination.routing_address.size = sizeof(this->connectionID);
    universal_message.has_from_destination = true;
    universal_message.from_destination = destination;
*/
    universal_message.which_payload = UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag;
    
    // The `flags` field is a bit mask of `universal_message.Flags` values.
    // Vehicles authenticate this value, but ignore unrecognized bits. Clients
    // should always set the `FLAG_ENCRYPT_RESPONSE` bit, which instructs vehicles
    // with compatible firmware (2024.38+) to encrypt the response.
    universal_message.flags = (1 << UniversalMessage_Flags_FLAG_ENCRYPT_RESPONSE);

    if (encryptPayload)
    {
      if (!session->isInitialized())
      {
        LOG_ERROR("Session not initialized");
        return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
      }

      pb_byte_t signature[16]; // AES-GCM tag
      pb_byte_t encrypted_payload[100];
      size_t encrypted_output_length = 0;
      uint32_t expires_at = session->generateExpiresAt(5);
      const pb_byte_t *epoch = session->getEpoch();

      // Construct AD buffer for encryption
      pb_byte_t ad_buffer[56];
      size_t ad_buffer_length = 0;
      session->ConstructADBuffer(
          Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
          this->VIN,
          expires_at,
          ad_buffer,
          &ad_buffer_length,
          universal_message.flags
      );

      // Generate nonce and encrypt payload
      pb_byte_t nonce[12];
      int return_code = session->Encrypt(
          payload,
          payload_length,
          encrypted_payload,
          sizeof(encrypted_payload),
          &encrypted_output_length,
          signature, // This will contain the AES-GCM tag
          ad_buffer,
          ad_buffer_length,
          nonce);

      if (return_code != 0)
      {
        LOG_ERROR("Failed to encrypt payload");
        return TeslaBLE_Status_E_ERROR_ENCRYPT;
      }

      // Set encrypted payload
      memcpy(universal_message.payload.protobuf_message_as_bytes.bytes,
            encrypted_payload,
            encrypted_output_length);
      universal_message.payload.protobuf_message_as_bytes.size = encrypted_output_length;

      // Prepare signature data
//      Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;
      
      // Set signer identity (public key)
      universal_message.sub_sigData.signature_data.signer_identity = Signatures_KeyIdentity_init_default;
      universal_message.sub_sigData.signature_data.signer_identity.which_identity_type = Signatures_KeyIdentity_public_key_tag;
      memcpy(universal_message.sub_sigData.signature_data.signer_identity.identity_type.public_key.bytes,
            this->public_key_,
            this->public_key_size_);
      universal_message.sub_sigData.signature_data.signer_identity.identity_type.public_key.size = this->public_key_size_;
      universal_message.sub_sigData.signature_data.has_signer_identity = true;
/*
      Signatures_KeyIdentity signer_identity = Signatures_KeyIdentity_init_default;
      signer_identity.which_identity_type = Signatures_KeyIdentity_public_key_tag;
      memcpy(signer_identity.identity_type.public_key.bytes,
            this->public_key_,
            this->public_key_size_);
      signer_identity.identity_type.public_key.size = this->public_key_size_;
      signature_data.has_signer_identity = true;
      signature_data.signer_identity = signer_identity;
*/
      // Set AES-GCM signature data
      Signatures_AES_GCM_Personalized_Signature_Data aes_gcm_signature_data = Signatures_AES_GCM_Personalized_Signature_Data_init_default;
      universal_message.sub_sigData.signature_data.which_sig_type = Signatures_SignatureData_AES_GCM_Personalized_data_tag;
      universal_message.sub_sigData.signature_data.sig_type.AES_GCM_Personalized_data.counter = session->getCounter();
      universal_message.sub_sigData.signature_data.sig_type.AES_GCM_Personalized_data.expires_at = expires_at;
      memcpy(universal_message.sub_sigData.signature_data.sig_type.AES_GCM_Personalized_data.nonce, nonce, sizeof nonce);
      memcpy(universal_message.sub_sigData.signature_data.sig_type.AES_GCM_Personalized_data.epoch, epoch, 16);
      memcpy(universal_message.sub_sigData.signature_data.sig_type.AES_GCM_Personalized_data.tag, signature, sizeof signature);

      // After storing the signature/tag, construct and store request hash for later use in decrypting responses
      pb_byte_t request_hash[17]; // Max size: 1 byte type + 16 bytes tag
      size_t request_hash_length;
      return_code = session->ConstructRequestHash(
          Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
          signature, // The tag we just generated
          sizeof(signature),
          request_hash,
          &request_hash_length);
          
      if (return_code != 0)
      {
          LOG_ERROR("Failed to construct request hash");
          return return_code;
      }

      // Store the request hash for later use
      memcpy(this->last_request_hash_, request_hash, request_hash_length);
      this->last_request_hash_length_ = request_hash_length;

      // Store the tag for later use in request hash construction
      memcpy(this->last_request_tag_, signature, sizeof(signature));
      this->last_request_type_ = Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED;

      universal_message.which_sub_sigData = UniversalMessage_RoutableMessage_signature_data_tag;
//      universal_message.sub_sigData.signature_data = signature_data;
    }
    else
    {
      memcpy(universal_message.payload.protobuf_message_as_bytes.bytes, payload, payload_length);
      universal_message.payload.protobuf_message_as_bytes.size = payload_length;
    }

    // random 16 bytes using rand()
    pb_byte_t uuid[16];
    for (int i = 0; i < sizeof(uuid); i++)
    {
      uuid[i] = rand() % 256;
    }
    memcpy(universal_message.uuid.bytes, uuid, sizeof(uuid));
    universal_message.uuid.size = sizeof(uuid);

    int return_code = pb_encode_fields(output_buffer, output_length, UniversalMessage_RoutableMessage_fields, &universal_message);
    if (return_code != 0)
    {
      LOG_ERROR("[buildUniversalMessageWithPayload] Failed to encode universal message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    return 0;
  }

  /*
   * This build the message to ask the car for his
   * ephemeral public key
   *
   * @param output_buffer Pointer to the output buffer
   * @param output_length Size of the output buffer
   * @return int result code 0 for successful
   */
  int Client::buildSessionInfoRequestMessage(UniversalMessage_Domain domain,
                                             pb_byte_t *output_buffer,
                                             size_t *output_length)
  {
    UniversalMessage_RoutableMessage universal_message = UniversalMessage_RoutableMessage_init_default;

    //Reuse destination rather than have different ones for from and to
    universal_message.to_destination                         = UniversalMessage_Destination_init_default;
    universal_message.to_destination.which_sub_destination   = UniversalMessage_Destination_domain_tag;
    universal_message.to_destination.sub_destination.domain  = domain;
    universal_message.has_to_destination                     = true;

/*    UniversalMessage_Destination destination = UniversalMessage_Destination_init_default;
    destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
    destination.sub_destination.domain = domain;
    universal_message.has_to_destination = true;
    universal_message.to_destination = destination;
*/
    universal_message.from_destination                                      = UniversalMessage_Destination_init_default;
    universal_message.from_destination.which_sub_destination                = UniversalMessage_Destination_routing_address_tag;
    memcpy(universal_message.from_destination.sub_destination.routing_address.bytes, this->connectionID, sizeof(this->connectionID));
    universal_message.from_destination.sub_destination.routing_address.size = sizeof(this->connectionID);
    universal_message.has_from_destination                                  = true;

/*    destination = UniversalMessage_Destination_init_default; // reset
    destination.which_sub_destination = UniversalMessage_Destination_routing_address_tag;
    memcpy(destination.sub_destination.routing_address.bytes, this->connectionID, sizeof(this->connectionID));
    destination.sub_destination.routing_address.size = sizeof(this->connectionID);
    universal_message.has_from_destination = true;
    universal_message.from_destination = destination;
*/
    universal_message.which_payload                                = UniversalMessage_RoutableMessage_session_info_request_tag;
    universal_message.payload.session_info_request                 = UniversalMessage_SessionInfoRequest_init_default;
    memcpy(universal_message.payload.session_info_request.public_key.bytes, this->public_key_, this->public_key_size_);
    universal_message.payload.session_info_request.public_key.size = this->public_key_size_;

    // generate unique uuid for the request
    pb_byte_t uuid[16];
    for (int i = 0; i < sizeof(uuid); i++)
    {
      uuid[i] = rand() % 256;
    }
    memcpy(universal_message.uuid.bytes, uuid, sizeof(uuid));
    universal_message.uuid.size = sizeof(uuid);

    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
/*    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int return_code = pb_encode_fields(universal_encode_buffer, &universal_encode_buffer_size, UniversalMessage_RoutableMessage_fields, &universal_message);
    if (return_code != 0)
    {
      LOG_ERROR("[buildSessionInfoRequest] Failed to encode universal message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    } */
    int return_code = pb_encode_fields(output_buffer + 2, &universal_encode_buffer_size, UniversalMessage_RoutableMessage_fields, &universal_message);
    if (return_code != 0)
    {
      LOG_ERROR("[buildSessionInfoRequest] Failed to encode universal message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    this->insertLength(universal_encode_buffer_size, output_buffer, output_length);

/*    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
*/
    return 0;
  }

  /*
   * This will build an unsigned message
   *
   * @param message Pointer to the message
   * @param output_buffer Pointer to the output buffer
   * @param output_length Size of the output buffer
   * @return int result code 0 for successful
   */
  int Client::buildUnsignedMessagePayload(VCSEC_UnsignedMessage *message,
                                          pb_byte_t *output_buffer,
                                          size_t *output_length,
                                          bool encryptPayload)
  {
    pb_byte_t payload_buffer[VCSEC_UnsignedMessage_size];
    size_t payload_length;
    // printf("message: %p\n", message);
    // printf("message.which_sub_message: %d\n", message->which_sub_message);
    int return_code = pb_encode_fields(payload_buffer, &payload_length, VCSEC_UnsignedMessage_fields, message);
    if (return_code != 0)
    {
      LOG_ERROR("[buildUnsignedMessagePayload] Failed to encode unsigned message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }

    // build universal message
    return this->buildUniversalMessageWithPayload(
        payload_buffer, payload_length, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
        output_buffer, output_length, encryptPayload);
  }

  int Client::buildKeySummary(pb_byte_t *output_buffer,
                              size_t *output_length)
  {
/*    VCSEC_InformationRequest informationRequest = VCSEC_InformationRequest_init_default;
    informationRequest.informationRequestType = VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO;

    VCSEC_UnsignedMessage payload = VCSEC_UnsignedMessage_init_default;
    payload.which_sub_message = VCSEC_UnsignedMessage_InformationRequest_tag;
    payload.sub_message.InformationRequest = informationRequest;
*/
    VCSEC_UnsignedMessage payload                                 = VCSEC_UnsignedMessage_init_default;
    payload.which_sub_message                                     = VCSEC_UnsignedMessage_InformationRequest_tag;
    payload.sub_message.InformationRequest                        = VCSEC_InformationRequest_init_default;
    payload.sub_message.InformationRequest.informationRequestType = VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO;

    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
    int status = this->buildUnsignedMessagePayload(&payload, output_buffer+(&output_buffer[2]-&output_buffer[0]), &universal_encode_buffer_size, false);
    if (status != 0)
    {
      LOG_ERROR("[buildKeySummary] Failed to build unsigned message\n");
      return status;
    }
    this->insertLength(universal_encode_buffer_size, output_buffer, output_length);
    return 0;
  }

  int Client::buildCarServerActionPayload(CarServer_Action *action,
                                          pb_byte_t *output_buffer,
                                          size_t *output_length)
  {
    pb_byte_t payload_buffer[UniversalMessage_RoutableMessage_size];
    size_t payload_length = 0;
    int return_code = pb_encode_fields(payload_buffer, &payload_length, CarServer_Action_fields, action);
    ESP_LOGD (TAG, "Payload buffer contents: %s length = %d", format_hex(payload_buffer, payload_length).c_str(), payload_length);
    if (return_code != 0)
    {
      LOG_ERROR("Failed to encode car action message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    // build universal message
    return_code = this->buildUniversalMessageWithPayload(
        payload_buffer, payload_length, UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
        output_buffer, output_length, true);
    if (return_code != 0)
    {
      LOG_ERROR("Failed to build car action message");       
      return 1;
    }
    return 0;
  }

  /*/
   * This will build an carserver action message to for
   * example open the trunk
   *
   * @param message Pointer to the message
   * @param output_buffer Pointer to the output buffer
   * @param output_length Size of the output buffer
   * @return int result code 0 for successful
   */

  int Client::buildCarServerActionMessage(const CarServer_VehicleAction *vehicle_action,
                                          pb_byte_t *output_buffer,
                                          size_t *output_length)
  {
    CarServer_Action action = CarServer_Action_init_default;
    action.which_action_msg = CarServer_Action_vehicleAction_tag;
    action.action_msg.vehicleAction = *vehicle_action;

    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
//    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildCarServerActionPayload(&action, output_buffer+(&output_buffer[2]-&output_buffer[0]), &universal_encode_buffer_size);
//    int status = this->buildCarServerActionPayload(&action, universal_encode_buffer, &universal_encode_buffer_size);
    if (status != 0)
    {
      LOG_ERROR("Failed to build car action message");
      return status;
    }
    this->insertLength(universal_encode_buffer_size, output_buffer, output_length);
/*    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
*/    return 0;
  }

  int Client::buildCarServerGetVehicleDataMessage (pb_byte_t *output_buffer,
                                                   size_t *output_length,
                                                   int which_get
                                                  )
  /*
  *   Function to build a CarServer_GetVehicleData message.
  */
  {
    // Build generic part
    CarServer_Action action                                           = CarServer_Action_init_default;
    action.which_action_msg                                           = CarServer_Action_vehicleAction_tag;
    action.action_msg.vehicleAction                                   = CarServer_VehicleAction_init_default;
     action.action_msg.vehicleAction.which_vehicle_action_msg         = CarServer_VehicleAction_getVehicleData_tag;
    action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData = CarServer_GetVehicleData_init_default;
    // Now the get specific part
    switch (which_get)
    {
      case CarServer_GetVehicleData_getChargeState_tag:
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.getChargeState     = CarServer_GetChargeState_init_default;
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.has_getChargeState = true;
        break;
      case CarServer_GetVehicleData_getClimateState_tag:
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.getClimateState     = CarServer_GetClimateState_init_default;
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.has_getClimateState = true;
        break;
      case CarServer_GetVehicleData_getDriveState_tag:
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.getDriveState     = CarServer_GetDriveState_init_default;
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.has_getDriveState = true;
        break;
      case CarServer_GetVehicleData_getLocationState_tag:
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.getLocationState     = CarServer_GetLocationState_init_default;
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.has_getLocationState = true;
        break;
      case CarServer_GetVehicleData_getClosuresState_tag:
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.getClosuresState     = CarServer_GetClosuresState_init_default;
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.has_getClosuresState = true;
        break;
      case CarServer_GetVehicleData_getTirePressureState_tag:
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.getTirePressureState     = CarServer_GetTirePressureState_init_default;
        action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.has_getTirePressureState = true;
        break;
      default:
        LOG_ERROR ("Invalid which_get type, action message not built");
        return 1;
    }
    // Add it to the message
/*    vehicle_action.vehicle_action_msg.getVehicleData = get_vehicle_data;
    action.action_msg.vehicleAction = vehicle_action;
*/    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
    //pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildCarServerActionPayload(&action, output_buffer+(&output_buffer[2]-&output_buffer[0]), &universal_encode_buffer_size);
    if (status != 0)
    {
      LOG_ERROR("[buildCarServerGetVehicleDataMessage] Failed to build car action message");
      return status;
    }
/*    universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
    pb_byte_t universal_encode_buffer2[universal_encode_buffer_size];
    status = this->buildCarServerActionPayload(&action2, universal_encode_buffer2, &universal_encode_buffer_size);
    if (status != 0)
    {
      LOG_ERROR("[buildCarServerGetVehicleDataMessage] Failed to build car action message");
      return status;
    }
*/
    this->insertLength(universal_encode_buffer_size, output_buffer, output_length);
    return 0;

  }

  int Client::buildCarServerVehicleActionMessage (int32_t set_value,
                                                  pb_byte_t *output_buffer,
                                                  size_t *output_length,
                                                  int which_tag
                                                 )
  {
    // Build generic part action.action_msg.vehicleAction
    CarServer_Action action = CarServer_Action_init_default;
    action.which_action_msg = CarServer_Action_vehicleAction_tag;
    action.action_msg.vehicleAction = CarServer_VehicleAction_init_default;
    action.action_msg.vehicleAction.which_vehicle_action_msg = which_tag;
    // Now the  specific part. Should be a switch but bizzarely doesn't compile!
    if (which_tag == CarServer_VehicleAction_setChargingAmpsAction_tag) 
    {
      action.action_msg.vehicleAction.vehicle_action_msg.setChargingAmpsAction               = CarServer_SetChargingAmpsAction_init_default;
      action.action_msg.vehicleAction.vehicle_action_msg.setChargingAmpsAction.charging_amps = set_value;
    }
    else if (which_tag == CarServer_VehicleAction_chargingSetLimitAction_tag)
    {
      action.action_msg.vehicleAction.vehicle_action_msg.chargingSetLimitAction         = CarServer_ChargingSetLimitAction_init_default;
      action.action_msg.vehicleAction.vehicle_action_msg.chargingSetLimitAction.percent = set_value;
    }
    else if (which_tag == CarServer_VehicleAction_chargingStartStopAction_tag)
    {
      action.action_msg.vehicleAction.vehicle_action_msg.chargingStartStopAction = CarServer_ChargingStartStopAction_init_default;
      if (set_value == 1)
      {
        action.action_msg.vehicleAction.vehicle_action_msg.chargingStartStopAction.which_charging_action = CarServer_ChargingStartStopAction_start_tag;
        action.action_msg.vehicleAction.vehicle_action_msg.chargingStartStopAction.charging_action.start = CarServer_Void_init_default;
      }
      else
      {
        action.action_msg.vehicleAction.vehicle_action_msg.chargingStartStopAction.which_charging_action = CarServer_ChargingStartStopAction_stop_tag;
        action.action_msg.vehicleAction.vehicle_action_msg.chargingStartStopAction.charging_action.stop  = CarServer_Void_init_default;
      }
    }
    else if (which_tag == CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag)
    {
      action.action_msg.vehicleAction.vehicle_action_msg.vehicleControlSetSentryModeAction    = CarServer_VehicleControlSetSentryModeAction_init_default;
      action.action_msg.vehicleAction.vehicle_action_msg.vehicleControlSetSentryModeAction.on = (set_value != 0);
    }
    else if (which_tag == CarServer_VehicleAction_hvacAutoAction_tag)
    {
      action.action_msg.vehicleAction.vehicle_action_msg.hvacAutoAction          = CarServer_HvacAutoAction_init_default;
      action.action_msg.vehicleAction.vehicle_action_msg.hvacAutoAction.power_on = (set_value != 0);
    }
    else if (which_tag == CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag)
    {
      action.action_msg.vehicleAction.vehicle_action_msg.hvacSteeringWheelHeaterAction          = CarServer_HvacSteeringWheelHeaterAction_init_default;
      action.action_msg.vehicleAction.vehicle_action_msg.hvacSteeringWheelHeaterAction.power_on = (set_value != 0);
    }
    else if (which_tag == CarServer_VehicleAction_chargePortDoorOpen_tag)
    {
      action.action_msg.vehicleAction.vehicle_action_msg.chargePortDoorOpen             = CarServer_ChargePortDoorOpen_init_default;
      action.action_msg.vehicleAction.vehicle_action_msg.chargePortDoorOpen.dummy_field = 1;
    }
    else if (which_tag == CarServer_VehicleAction_chargePortDoorClose_tag)
    {
      action.action_msg.vehicleAction.vehicle_action_msg.chargePortDoorClose             = CarServer_ChargePortDoorClose_init_default;
      action.action_msg.vehicleAction.vehicle_action_msg.chargePortDoorClose.dummy_field = 1;
    }
    else if (which_tag == CarServer_VehicleAction_vehicleControlFlashLightsAction_tag)
    {
      action.action_msg.vehicleAction.vehicle_action_msg.vehicleControlFlashLightsAction             = CarServer_VehicleControlFlashLightsAction_init_default;
      action.action_msg.vehicleAction.vehicle_action_msg.vehicleControlFlashLightsAction.dummy_field = 1;
    }
    else if (which_tag == CarServer_VehicleAction_vehicleControlHonkHornAction_tag)
    {
      action.action_msg.vehicleAction.vehicle_action_msg.vehicleControlHonkHornAction             = CarServer_VehicleControlHonkHornAction_init_default;
      action.action_msg.vehicleAction.vehicle_action_msg.vehicleControlHonkHornAction.dummy_field = 1;
    }
    else if (which_tag == CarServer_VehicleAction_vehicleControlWindowAction_tag)
    {
      action.action_msg.vehicleAction.vehicle_action_msg.vehicleControlWindowAction = CarServer_VehicleControlWindowAction_init_default;
      if (set_value == 1)
      {
        action.action_msg.vehicleAction.vehicle_action_msg.vehicleControlWindowAction.which_action = CarServer_VehicleControlWindowAction_vent_tag;
        action.action_msg.vehicleAction.vehicle_action_msg.vehicleControlWindowAction.action.vent  = CarServer_Void_init_default;
      }
      else
      {
        action.action_msg.vehicleAction.vehicle_action_msg.vehicleControlWindowAction.which_action = CarServer_VehicleControlWindowAction_close_tag;
        action.action_msg.vehicleAction.vehicle_action_msg.vehicleControlWindowAction.action.close = CarServer_Void_init_default;
      }
    }
    else if (which_tag == CarServer_VehicleAction_hvacSetPreconditioningMaxAction_tag)
    {
      action.action_msg.vehicleAction.vehicle_action_msg.hvacSetPreconditioningMaxAction    = CarServer_HvacSetPreconditioningMaxAction_init_default;
      action.action_msg.vehicleAction.vehicle_action_msg.hvacSetPreconditioningMaxAction.on = (set_value != 0);
    }
    else
    {
      LOG_ERROR ("Invalid which_tag type, car server vehicle action message not built");
      return 1;
    }
    // Add it to the message
//    action.action_msg.vehicleAction = vehicle_action;

    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
//    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildCarServerActionPayload(&action, output_buffer+(&output_buffer[2]-&output_buffer[0]), &universal_encode_buffer_size);
//    int status = this->buildCarServerActionPayload(&action, universal_encode_buffer, &universal_encode_buffer_size);
    if (status != 0)
    {
        LOG_ERROR ("Failed to build car server vehicle action message");
        return status;
    }
    this->insertLength(universal_encode_buffer_size, output_buffer, output_length);
//    this->prependLength(universal_encode_buffer, universal_encode_buffer_size, output_buffer, output_length);
    return 0;
  }

  int Client::buildVCSECActionMessage(const VCSEC_RKEAction_E action, pb_byte_t *output_buffer,
                                      size_t *output_length)
  {
    VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
    unsigned_message.which_sub_message     = VCSEC_UnsignedMessage_RKEAction_tag;
    unsigned_message.sub_message.RKEAction = action;

    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
//    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildUnsignedMessagePayload(&unsigned_message, output_buffer+(&output_buffer[2]-&output_buffer[0]), &universal_encode_buffer_size, true);
//    int status = this->buildUnsignedMessagePayload(&unsigned_message, universal_encode_buffer, &universal_encode_buffer_size, true);
    if (status != 0)
    {
      LOG_ERROR("Failed to build unsigned message");
      return status;
    }
    this->insertLength(universal_encode_buffer_size, output_buffer, output_length);
//    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
//                        output_buffer, output_length);
    return 0;
  }

  int Client::buildVCSECClosureMoveRequestMessage (const VCSEC_ClosureMoveRequest request,
                                                   pb_byte_t *output_buffer,
                                                   size_t *output_length)
  {
    VCSEC_UnsignedMessage unsigned_message          = VCSEC_UnsignedMessage_init_default;
    unsigned_message.which_sub_message              = VCSEC_UnsignedMessage_closureMoveRequest_tag;
    unsigned_message.sub_message.closureMoveRequest = request;

    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
//    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildUnsignedMessagePayload(&unsigned_message, output_buffer+(&output_buffer[2]-&output_buffer[0]), &universal_encode_buffer_size, true);
//    int status = this->buildUnsignedMessagePayload(&unsigned_message, universal_encode_buffer, &universal_encode_buffer_size, true);
    if (status != 0)
    {
      LOG_ERROR("Failed to build unsigned message");
      return status;
    }
    this->insertLength(universal_encode_buffer_size, output_buffer, output_length);
//    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
//                        output_buffer, output_length);
    return 0;
  }

  int Client::buildVCSECInformationRequestMessage(VCSEC_InformationRequestType request_type,
                                                  pb_byte_t *output_buffer,
                                                  size_t *output_length,
                                                  uint32_t key_slot)
  {
    VCSEC_UnsignedMessage unsigned_message                                 = VCSEC_UnsignedMessage_init_default;
    unsigned_message.which_sub_message                                     = VCSEC_UnsignedMessage_InformationRequest_tag;
    unsigned_message.sub_message.InformationRequest                        = VCSEC_InformationRequest_init_zero;
    unsigned_message.sub_message.InformationRequest.informationRequestType = request_type;
    if (key_slot != 0xFFFFFFFF)
    {
      // printf("Adding key slot info");
      unsigned_message.sub_message.InformationRequest.which_key = VCSEC_InformationRequest_slot_tag;
      unsigned_message.sub_message.InformationRequest.key.slot = key_slot;
    }

    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
//    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildUnsignedMessagePayload (&unsigned_message, output_buffer+(&output_buffer[2]-&output_buffer[0]), &universal_encode_buffer_size, false);
//    int status = this->buildUnsignedMessagePayload(&unsigned_message, universal_encode_buffer, &universal_encode_buffer_size, false);
    if (status != 0)
    {
      LOG_ERROR("Failed to build unsigned message");
      return status;
    }
    this->insertLength (universal_encode_buffer_size, output_buffer, output_length);
//    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
//                        output_buffer, output_length);
    return 0;
  }
} // namespace TeslaBLE
// #endif // MBEDTLS_CONFIG_FILE
