/*
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.signalservice.api;

import com.google.protobuf.ByteString;

import org.signal.libsignal.metadata.certificate.SenderCertificate;
import org.signal.zkgroup.profiles.ClientZkProfileOperations;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidRegistrationIdException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.groups.GroupSessionBuilder;
import org.whispersystems.libsignal.logging.Log;
import org.whispersystems.libsignal.protocol.DecryptionErrorMessage;
import org.whispersystems.libsignal.protocol.PlaintextContent;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.util.Pair;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.libsignal.util.guava.Preconditions;
import org.whispersystems.signalservice.api.crypto.AttachmentCipherOutputStream;
import org.whispersystems.signalservice.api.crypto.ContentHint;
import org.whispersystems.signalservice.api.crypto.EnvelopeContent;
import org.whispersystems.signalservice.api.crypto.SignalGroupSessionBuilder;
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher;
import org.whispersystems.signalservice.api.crypto.SignalSessionBuilder;
import org.whispersystems.signalservice.api.crypto.UnidentifiedAccess;
import org.whispersystems.signalservice.api.crypto.UnidentifiedAccessPair;
import org.whispersystems.signalservice.api.crypto.UntrustedIdentityException;
import org.whispersystems.signalservice.api.messages.SendMessageResult;
import org.whispersystems.signalservice.api.messages.SignalServiceAttachment;
import org.whispersystems.signalservice.api.messages.SignalServiceAttachmentPointer;
import org.whispersystems.signalservice.api.messages.SignalServiceAttachmentRemoteId;
import org.whispersystems.signalservice.api.messages.SignalServiceAttachmentStream;
import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.signalservice.api.messages.SignalServiceGroup;
import org.whispersystems.signalservice.api.messages.SignalServiceGroupContext;
import org.whispersystems.signalservice.api.messages.SignalServiceGroupV2;
import org.whispersystems.signalservice.api.messages.SignalServicePreview;
import org.whispersystems.signalservice.api.messages.SignalServiceReceiptMessage;
import org.whispersystems.signalservice.api.messages.SignalServiceStoryMessage;
import org.whispersystems.signalservice.api.messages.SignalServiceTextAttachment;
import org.whispersystems.signalservice.api.messages.SignalServiceTypingMessage;
import org.whispersystems.signalservice.api.messages.calls.AnswerMessage;
import org.whispersystems.signalservice.api.messages.calls.CallingResponse;
import org.whispersystems.signalservice.api.messages.calls.IceUpdateMessage;
import org.whispersystems.signalservice.api.messages.calls.OfferMessage;
import org.whispersystems.signalservice.api.messages.calls.OpaqueMessage;
import org.whispersystems.signalservice.api.messages.calls.SignalServiceCallMessage;
import org.whispersystems.signalservice.api.messages.multidevice.BlockedListMessage;
import org.whispersystems.signalservice.api.messages.multidevice.ConfigurationMessage;
import org.whispersystems.signalservice.api.messages.multidevice.KeysMessage;
import org.whispersystems.signalservice.api.messages.multidevice.MessageRequestResponseMessage;
import org.whispersystems.signalservice.api.messages.multidevice.OutgoingPaymentMessage;
import org.whispersystems.signalservice.api.messages.multidevice.ReadMessage;
import org.whispersystems.signalservice.api.messages.multidevice.SentTranscriptMessage;
import org.whispersystems.signalservice.api.messages.multidevice.SignalServiceSyncMessage;
import org.whispersystems.signalservice.api.messages.multidevice.StickerPackOperationMessage;
import org.whispersystems.signalservice.api.messages.multidevice.VerifiedMessage;
import org.whispersystems.signalservice.api.messages.multidevice.ViewOnceOpenMessage;
import org.whispersystems.signalservice.api.messages.multidevice.ViewedMessage;
import org.whispersystems.signalservice.api.messages.shared.SharedContact;
import org.whispersystems.signalservice.api.push.ACI;
import org.whispersystems.signalservice.api.push.DistributionId;
import org.whispersystems.signalservice.api.push.ServiceId;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.exceptions.AuthorizationFailedException;
import org.whispersystems.signalservice.api.push.exceptions.MalformedResponseException;
import org.whispersystems.signalservice.api.push.exceptions.NonSuccessfulResponseCodeException;
import org.whispersystems.signalservice.api.push.exceptions.NotFoundException;
import org.whispersystems.signalservice.api.push.exceptions.ProofRequiredException;
import org.whispersystems.signalservice.api.push.exceptions.PushNetworkException;
import org.whispersystems.signalservice.api.push.exceptions.RateLimitException;
import org.whispersystems.signalservice.api.push.exceptions.ServerRejectedException;
import org.whispersystems.signalservice.api.push.exceptions.UnregisteredUserException;
import org.whispersystems.signalservice.api.services.AttachmentService;
import org.whispersystems.signalservice.api.services.MessagingService;
import org.whispersystems.signalservice.api.util.AttachmentPointerUtil;
import org.whispersystems.signalservice.api.util.CredentialsProvider;
import org.whispersystems.signalservice.api.util.Uint64RangeException;
import org.whispersystems.signalservice.api.util.Uint64Util;
import org.whispersystems.signalservice.api.websocket.WebSocketUnavailableException;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.crypto.PaddingInputStream;
import org.whispersystems.signalservice.internal.push.AttachmentV2UploadAttributes;
import org.whispersystems.signalservice.internal.push.AttachmentV3UploadAttributes;
import org.whispersystems.signalservice.internal.push.GroupMismatchedDevices;
import org.whispersystems.signalservice.internal.push.GroupStaleDevices;
import org.whispersystems.signalservice.internal.push.MismatchedDevices;
import org.whispersystems.signalservice.internal.push.OutgoingPushMessage;
import org.whispersystems.signalservice.internal.push.OutgoingPushMessageList;
import org.whispersystems.signalservice.internal.push.ProvisioningProtos;
import org.whispersystems.signalservice.internal.push.PushAttachmentData;
import org.whispersystems.signalservice.internal.push.PushServiceSocket;
import org.whispersystems.signalservice.internal.push.SendGroupMessageResponse;
import org.whispersystems.signalservice.internal.push.SendMessageResponse;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.AttachmentPointer;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.CallMessage;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.Content;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.DataMessage;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.GroupContext;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.GroupContextV2;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.NullMessage;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.Preview;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.ReceiptMessage;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.StoryMessage;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.SyncMessage;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.TextAttachment;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.TypingMessage;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.Verified;
import org.whispersystems.signalservice.internal.push.StaleDevices;
import org.whispersystems.signalservice.internal.push.exceptions.GroupMismatchedDevicesException;
import org.whispersystems.signalservice.internal.push.exceptions.GroupStaleDevicesException;
import org.whispersystems.signalservice.internal.push.exceptions.InvalidUnidentifiedAccessHeaderException;
import org.whispersystems.signalservice.internal.push.exceptions.MismatchedDevicesException;
import org.whispersystems.signalservice.internal.push.exceptions.StaleDevicesException;
import org.whispersystems.signalservice.internal.push.http.AttachmentCipherOutputStreamFactory;
import org.whispersystems.signalservice.internal.push.http.CancelationSignal;
import org.whispersystems.signalservice.internal.push.http.PartialSendCompleteListener;
import org.whispersystems.signalservice.internal.push.http.ResumableUploadSpec;
import org.whispersystems.signalservice.internal.util.Util;
import org.whispersystems.util.Base64;
import org.whispersystems.util.ByteArrayUtil;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

/**
 * The main interface for sending Signal Service messages.
 *
 * @author Moxie Marlinspike
 */
public class SignalServiceMessageSender {

  private static final String TAG = SignalServiceMessageSender.class.getSimpleName();

  private static final int RETRY_COUNT = 4;

  private final PushServiceSocket             socket;
  private final SignalServiceAccountDataStore store;
  private final SignalSessionLock             sessionLock;
  private final SignalServiceAddress          localAddress;
  private final int                           localDeviceId;
  private final Optional<EventListener>       eventListener;

  private final AttachmentService attachmentService;
  private final MessagingService  messagingService;

  private final ExecutorService executor;
  private final long            maxEnvelopeSize;

  public SignalServiceMessageSender(SignalServiceConfiguration urls,
                                    CredentialsProvider credentialsProvider,
                                    SignalServiceDataStore store,
                                    SignalSessionLock sessionLock,
                                    String signalAgent,
                                    SignalWebSocket signalWebSocket,
                                    Optional<EventListener> eventListener,
                                    ClientZkProfileOperations clientZkProfileOperations,
                                    ExecutorService executor,
                                    long maxEnvelopeSize,
                                    boolean automaticNetworkRetry)
  {
    this.socket            = new PushServiceSocket(urls, credentialsProvider, signalAgent, clientZkProfileOperations, automaticNetworkRetry);
    this.store             = store.aci();
    this.sessionLock       = sessionLock;
    this.localAddress      = new SignalServiceAddress(credentialsProvider.getAci(), credentialsProvider.getE164());
    this.localDeviceId     = credentialsProvider.getDeviceId();
    this.attachmentService = new AttachmentService(signalWebSocket);
    this.messagingService  = new MessagingService(signalWebSocket);
    this.eventListener     = eventListener;
    this.executor          = executor != null ? executor : Executors.newSingleThreadExecutor();
    this.maxEnvelopeSize   = maxEnvelopeSize;
  }

  /**
   * Send a read receipt for a received message.
   *
   * @param recipient The sender of the received message you're acknowledging.
   * @param message The read receipt to deliver.
   */
  public SendMessageResult sendReceipt(SignalServiceAddress recipient,
                                       Optional<UnidentifiedAccessPair> unidentifiedAccess,
                                       SignalServiceReceiptMessage message)
      throws IOException, UntrustedIdentityException
  {
    Content         content         = createReceiptContent(message);
    EnvelopeContent envelopeContent = EnvelopeContent.encrypted(content, ContentHint.IMPLICIT, Optional.absent());

    return sendMessage(recipient, getTargetUnidentifiedAccess(unidentifiedAccess), message.getWhen(), envelopeContent, false, null);
  }

  /**
   * Send a retry receipt for a bad-encrypted envelope.
   */
  public void sendRetryReceipt(SignalServiceAddress recipient,
                               Optional<UnidentifiedAccessPair> unidentifiedAccess,
                               Optional<byte[]> groupId,
                               DecryptionErrorMessage errorMessage)
      throws IOException, UntrustedIdentityException

  {
    PlaintextContent content         = new PlaintextContent(errorMessage);
    EnvelopeContent  envelopeContent = EnvelopeContent.plaintext(content, groupId);

    sendMessage(recipient, getTargetUnidentifiedAccess(unidentifiedAccess), System.currentTimeMillis(), envelopeContent, false, null);
  }

  /**
   * Sends a typing indicator using client-side fanout. Doesn't bother with return results, since these are best-effort.
   */
  public void sendTyping(List<SignalServiceAddress>             recipients,
                         List<Optional<UnidentifiedAccessPair>> unidentifiedAccess,
                         SignalServiceTypingMessage             message,
                         CancelationSignal                      cancelationSignal)
      throws IOException
  {
    Content         content         = createTypingContent(message);
    EnvelopeContent envelopeContent = EnvelopeContent.encrypted(content, ContentHint.IMPLICIT, Optional.absent());

    sendMessage(recipients, getTargetUnidentifiedAccess(unidentifiedAccess), message.getTimestamp(), envelopeContent, true, null, cancelationSignal);
  }

  /**
   * Send a typing indicator to a group using sender key. Doesn't bother with return results, since these are best-effort.
   */
  public void sendGroupTyping(DistributionId              distributionId,
                              List<SignalServiceAddress>  recipients,
                              List<UnidentifiedAccess>    unidentifiedAccess,
                              SignalServiceTypingMessage  message)
      throws IOException, UntrustedIdentityException, InvalidKeyException, NoSessionException, InvalidRegistrationIdException
  {
    Content content = createTypingContent(message);
    sendGroupMessage(distributionId, recipients, unidentifiedAccess, message.getTimestamp(), content, ContentHint.IMPLICIT, message.getGroupId(), true, SenderKeyGroupEvents.EMPTY);
  }

  public List<SendMessageResult> sendStory(List<SignalServiceAddress>             recipients,
                                           List<Optional<UnidentifiedAccessPair>> unidentifiedAccess,
                                           SignalServiceStoryMessage              message,
                                           long                                   timestamp)
      throws IOException, UntrustedIdentityException
  {
    Content         content         = createStoryContent(message);
    EnvelopeContent envelopeContent = EnvelopeContent.encrypted(content, ContentHint.RESENDABLE, Optional.absent());

    return sendMessage(recipients, getTargetUnidentifiedAccess(unidentifiedAccess), timestamp, envelopeContent, false, null, null);
  }

  /**
   * Send a typing indicator to a group using sender key. Doesn't bother with return results, since these are best-effort.
   * @return
   */
  public List<SendMessageResult> sendGroupStory(DistributionId              distributionId,
                                                Optional<byte[]>            groupId,
                                                List<SignalServiceAddress>  recipients,
                                                List<UnidentifiedAccess>    unidentifiedAccess,
                                                SignalServiceStoryMessage   message,
                                                long                        timestamp)
      throws IOException, UntrustedIdentityException, InvalidKeyException, NoSessionException, InvalidRegistrationIdException
  {
    Content content = createStoryContent(message);
    return sendGroupMessage(distributionId, recipients, unidentifiedAccess, timestamp, content, ContentHint.RESENDABLE, groupId, false, SenderKeyGroupEvents.EMPTY);
  }


  /**
   * Send a call setup message to a single recipient.
   *
   * @param recipient The message's destination.
   * @param message The call message.
   * @throws IOException
   */
  public void sendCallMessage(SignalServiceAddress recipient,
                              Optional<UnidentifiedAccessPair> unidentifiedAccess,
                              SignalServiceCallMessage message)
      throws IOException, UntrustedIdentityException
  {
    Content         content         = createCallContent(message);
    EnvelopeContent envelopeContent = EnvelopeContent.encrypted(content, ContentHint.DEFAULT, Optional.absent());

    sendMessage(recipient, getTargetUnidentifiedAccess(unidentifiedAccess), System.currentTimeMillis(), envelopeContent, false, null);
  }

  public List<SendMessageResult> sendCallMessage(List<SignalServiceAddress> recipients,
                                                 List<Optional<UnidentifiedAccessPair>> unidentifiedAccess,
                                                 SignalServiceCallMessage message)
      throws IOException
  {
    Content         content         = createCallContent(message);
    EnvelopeContent envelopeContent = EnvelopeContent.encrypted(content, ContentHint.DEFAULT, Optional.absent());

    return sendMessage(recipients, getTargetUnidentifiedAccess(unidentifiedAccess), System.currentTimeMillis(), envelopeContent, false, null, null);
  }

  public List<SendMessageResult> sendCallMessage(DistributionId distributionId,
                                                 List<SignalServiceAddress> recipients,
                                                 List<UnidentifiedAccess> unidentifiedAccess,
                                                 SignalServiceCallMessage message)
      throws IOException, UntrustedIdentityException, InvalidKeyException, NoSessionException, InvalidRegistrationIdException
  {
    Content content = createCallContent(message);
    return sendGroupMessage(distributionId, recipients, unidentifiedAccess, message.getTimestamp().get(), content, ContentHint.IMPLICIT, message.getGroupId(), false, SenderKeyGroupEvents.EMPTY);
  }

  /**
   * Send an http request on behalf of the calling infrastructure.
   *
   * @param requestId Request identifier
   * @param url Fully qualified URL to request
   * @param httpMethod Http method to use (e.g., "GET", "POST")
   * @param headers Optional list of headers to send with request
   * @param body Optional body to send with request
   * @return
   */
  public CallingResponse makeCallingRequest(long requestId, String url, String httpMethod, List<Pair<String, String>> headers, byte[] body) {
    return socket.makeCallingRequest(requestId, url, httpMethod, headers, body);
  }

  /**
   * Send a message to a single recipient.
   *
   * @param recipient The message's destination.
   * @param message The message.
   * @throws UntrustedIdentityException
   * @throws IOException
   */
  public SendMessageResult sendDataMessage(SignalServiceAddress             recipient,
                                           Optional<UnidentifiedAccessPair> unidentifiedAccess,
                                           ContentHint                      contentHint,
                                           SignalServiceDataMessage         message,
                                           IndividualSendEvents             sendEvents)
      throws UntrustedIdentityException, IOException
  {
    Log.d(TAG, "[" + message.getTimestamp() + "] Sending a data message.");

    Content           content         = createMessageContent(message);
    EnvelopeContent   envelopeContent = EnvelopeContent.encrypted(content, contentHint, message.getGroupId());

    sendEvents.onMessageEncrypted();

    long              timestamp = message.getTimestamp();
    SendMessageResult result    = sendMessage(recipient, getTargetUnidentifiedAccess(unidentifiedAccess), timestamp, envelopeContent, false, null);

    sendEvents.onMessageSent();

    if (result.getSuccess() != null && result.getSuccess().isNeedsSync()) {
      Content         syncMessage        = createMultiDeviceSentTranscriptContent(content, Optional.of(recipient), timestamp, Collections.singletonList(result), false);
      EnvelopeContent syncMessageContent = EnvelopeContent.encrypted(syncMessage, ContentHint.IMPLICIT, Optional.absent());

      sendMessage(localAddress, Optional.absent(), timestamp, syncMessageContent, false, null);
    }

    sendEvents.onSyncMessageSent();

    return result;
  }

  /**
   * Gives you a {@link SenderKeyDistributionMessage} that can then be sent out to recipients to tell them about your sender key.
   * Will create a sender key session for the provided DistributionId if one doesn't exist.
   */
  public SenderKeyDistributionMessage getOrCreateNewGroupSession(DistributionId distributionId) {
    SignalProtocolAddress self = new SignalProtocolAddress(localAddress.getIdentifier(), localDeviceId);
    return new SignalGroupSessionBuilder(sessionLock, new GroupSessionBuilder(store)).create(self, distributionId.asUuid());
  }

  /**
   * Sends the provided {@link SenderKeyDistributionMessage} to the specified recipients.
   */
  public List<SendMessageResult> sendSenderKeyDistributionMessage(DistributionId                         distributionId,
                                                                  List<SignalServiceAddress>             recipients,
                                                                  List<Optional<UnidentifiedAccessPair>> unidentifiedAccess,
                                                                  SenderKeyDistributionMessage           message,
                                                                  Optional<byte[]>                       groupId)
      throws IOException
  {
    ByteString      distributionBytes = ByteString.copyFrom(message.serialize());
    Content         content           = Content.newBuilder().setSenderKeyDistributionMessage(distributionBytes).build();
    EnvelopeContent envelopeContent   = EnvelopeContent.encrypted(content, ContentHint.IMPLICIT, groupId);
    long            timestamp         = System.currentTimeMillis();

    Log.d(TAG, "[" + timestamp + "] Sending SKDM to " + recipients.size() + " recipients for DistributionId " + distributionId);
    return sendMessage(recipients, getTargetUnidentifiedAccess(unidentifiedAccess), timestamp, envelopeContent, false, null, null);
  }

  /**
   * Processes an inbound {@link SenderKeyDistributionMessage}.
   */
  public void processSenderKeyDistributionMessage(SignalProtocolAddress sender, SenderKeyDistributionMessage senderKeyDistributionMessage) {
    new SignalGroupSessionBuilder(sessionLock, new GroupSessionBuilder(store)).process(sender, senderKeyDistributionMessage);
  }

  /**
   * Resend a previously-sent message.
   */
  public SendMessageResult resendContent(SignalServiceAddress address,
                                         Optional<UnidentifiedAccessPair> unidentifiedAccess,
                                         long timestamp,
                                         Content content,
                                         ContentHint contentHint,
                                         Optional<byte[]> groupId)
      throws UntrustedIdentityException, IOException
  {
    EnvelopeContent              envelopeContent = EnvelopeContent.encrypted(content, contentHint, groupId);
    Optional<UnidentifiedAccess> access          = unidentifiedAccess.isPresent() ? unidentifiedAccess.get().getTargetUnidentifiedAccess() : Optional.absent();

    return sendMessage(address, access, timestamp, envelopeContent, false, null);
  }

  /**
   * Sends a {@link SignalServiceDataMessage} to a group using sender keys.
   */
  public List<SendMessageResult> sendGroupDataMessage(DistributionId             distributionId,
                                                      List<SignalServiceAddress> recipients,
                                                      List<UnidentifiedAccess>   unidentifiedAccess,
                                                      boolean                    isRecipientUpdate,
                                                      ContentHint                contentHint,
                                                      SignalServiceDataMessage   message,
                                                      SenderKeyGroupEvents       sendEvents)
      throws IOException, UntrustedIdentityException, NoSessionException, InvalidKeyException, InvalidRegistrationIdException
  {
    Log.d(TAG, "[" + message.getTimestamp() + "] Sending a group data message to " + recipients.size() + " recipients using DistributionId " + distributionId);

    Content                 content = createMessageContent(message);
    Optional<byte[]>        groupId = message.getGroupId();
    List<SendMessageResult> results = sendGroupMessage(distributionId, recipients, unidentifiedAccess, message.getTimestamp(), content, contentHint, groupId, false, sendEvents);

    sendEvents.onMessageSent();

    if (store.isMultiDevice()) {
      Content         syncMessage        = createMultiDeviceSentTranscriptContent(content, Optional.absent(), message.getTimestamp(), results, isRecipientUpdate);
      EnvelopeContent syncMessageContent = EnvelopeContent.encrypted(syncMessage, ContentHint.IMPLICIT, Optional.absent());

      sendMessage(localAddress, Optional.absent(), message.getTimestamp(), syncMessageContent, false, null);
    }

    sendEvents.onSyncMessageSent();

    return results;
  }

  /**
   * Sends a message to a group using client-side fanout.
   *
   * @param partialListener A listener that will be called when an individual send is completed. Will be invoked on an arbitrary background thread, *not*
   *                        the calling thread.
   */
  public List<SendMessageResult> sendDataMessage(List<SignalServiceAddress>             recipients,
                                                 List<Optional<UnidentifiedAccessPair>> unidentifiedAccess,
                                                 boolean                                isRecipientUpdate,
                                                 ContentHint                            contentHint,
                                                 SignalServiceDataMessage               message,
                                                 LegacyGroupEvents                      sendEvents,
                                                 PartialSendCompleteListener            partialListener,
                                                 CancelationSignal                      cancelationSignal)
      throws IOException, UntrustedIdentityException
  {
    Log.d(TAG, "[" + message.getTimestamp() + "] Sending a data message to " + recipients.size() + " recipients.");

    Content                 content            = createMessageContent(message);
    EnvelopeContent         envelopeContent    = EnvelopeContent.encrypted(content, contentHint, message.getGroupId());
    long                    timestamp          = message.getTimestamp();
    List<SendMessageResult> results            = sendMessage(recipients, getTargetUnidentifiedAccess(unidentifiedAccess), timestamp, envelopeContent, false, partialListener, cancelationSignal);
    boolean                 needsSyncInResults = false;

    sendEvents.onMessageSent();

    for (SendMessageResult result : results) {
      if (result.getSuccess() != null && result.getSuccess().isNeedsSync()) {
        needsSyncInResults = true;
        break;
      }
    }

    if (needsSyncInResults || store.isMultiDevice()) {
      Optional<SignalServiceAddress> recipient = Optional.absent();
      if (!message.getGroupContext().isPresent() && recipients.size() == 1) {
        recipient = Optional.of(recipients.get(0));
      }

      Content         syncMessage        = createMultiDeviceSentTranscriptContent(content, recipient, timestamp, results, isRecipientUpdate);
      EnvelopeContent syncMessageContent = EnvelopeContent.encrypted(syncMessage, ContentHint.IMPLICIT, Optional.absent());

      sendMessage(localAddress, Optional.absent(), timestamp, syncMessageContent, false, null);
    }

    sendEvents.onSyncMessageSent();

    return results;
  }

  public SendMessageResult sendSyncMessage(SignalServiceDataMessage dataMessage)
      throws IOException, UntrustedIdentityException
  {
    return sendSyncMessage(createSelfSendSyncMessage(dataMessage), Optional.absent());
  }

  public SendMessageResult sendSyncMessage(SignalServiceSyncMessage message, Optional<UnidentifiedAccessPair> unidentifiedAccess)
      throws IOException, UntrustedIdentityException
  {
    Content content;

    if (message.getContacts().isPresent()) {
      content = createMultiDeviceContactsContent(message.getContacts().get().getContactsStream().asStream(),
                                                 message.getContacts().get().isComplete());
    } else if (message.getGroups().isPresent()) {
      content = createMultiDeviceGroupsContent(message.getGroups().get().asStream());
    } else if (message.getRead().isPresent()) {
      content = createMultiDeviceReadContent(message.getRead().get());
    } else if (message.getViewed().isPresent()) {
      content = createMultiDeviceViewedContent(message.getViewed().get());
    } else if (message.getViewOnceOpen().isPresent()) {
      content = createMultiDeviceViewOnceOpenContent(message.getViewOnceOpen().get());
    } else if (message.getBlockedList().isPresent()) {
      content = createMultiDeviceBlockedContent(message.getBlockedList().get());
    } else if (message.getConfiguration().isPresent()) {
      content = createMultiDeviceConfigurationContent(message.getConfiguration().get());
    } else if (message.getSent().isPresent()) {
      content = createMultiDeviceSentTranscriptContent(message.getSent().get(), unidentifiedAccess.isPresent());
    } else if (message.getStickerPackOperations().isPresent()) {
      content = createMultiDeviceStickerPackOperationContent(message.getStickerPackOperations().get());
    } else if (message.getFetchType().isPresent()) {
      content = createMultiDeviceFetchTypeContent(message.getFetchType().get());
    } else if (message.getMessageRequestResponse().isPresent()) {
      content = createMultiDeviceMessageRequestResponseContent(message.getMessageRequestResponse().get());
    } else if (message.getOutgoingPaymentMessage().isPresent()) {
      content = createMultiDeviceOutgoingPaymentContent(message.getOutgoingPaymentMessage().get());
    } else if (message.getKeys().isPresent()) {
      content = createMultiDeviceSyncKeysContent(message.getKeys().get());
    } else if (message.getVerified().isPresent()) {
      return sendVerifiedSyncMessage(message.getVerified().get());
    } else if (message.getRequest().isPresent()) {
      content = createRequestContent(message.getRequest().get().getRequest());
    } else {
      throw new IOException("Unsupported sync message!");
    }

    long timestamp = message.getSent().isPresent() ? message.getSent().get().getTimestamp()
                                                   : System.currentTimeMillis();

    EnvelopeContent envelopeContent = EnvelopeContent.encrypted(content, ContentHint.IMPLICIT, Optional.absent());

    return sendMessage(localAddress, Optional.absent(), timestamp, envelopeContent, false, null);
  }

  public void setSoTimeoutMillis(long soTimeoutMillis) {
    socket.setSoTimeoutMillis(soTimeoutMillis);
  }

  public void cancelInFlightRequests() {
    socket.cancelInFlightRequests();
  }

  public SignalServiceAttachmentPointer uploadAttachment(SignalServiceAttachmentStream attachment) throws IOException {
    byte[]             attachmentKey    = attachment.getResumableUploadSpec().transform(ResumableUploadSpec::getSecretKey).or(() -> Util.getSecretBytes(64));
    byte[]             attachmentIV     = attachment.getResumableUploadSpec().transform(ResumableUploadSpec::getIV).or(() -> Util.getSecretBytes(16));
    long               paddedLength     = PaddingInputStream.getPaddedSize(attachment.getLength());
    InputStream        dataStream       = new PaddingInputStream(attachment.getInputStream(), attachment.getLength());
    long               ciphertextLength = AttachmentCipherOutputStream.getCiphertextLength(paddedLength);
    PushAttachmentData attachmentData   = new PushAttachmentData(attachment.getContentType(),
                                                                 dataStream,
                                                                 ciphertextLength,
                                                                 new AttachmentCipherOutputStreamFactory(attachmentKey, attachmentIV),
                                                                 attachment.getListener(),
                                                                 attachment.getCancelationSignal(),
                                                                 attachment.getResumableUploadSpec().orNull());

    if (attachment.getResumableUploadSpec().isPresent()) {
      return uploadAttachmentV3(attachment, attachmentKey, attachmentData);
    } else {
      return uploadAttachmentV2(attachment, attachmentKey, attachmentData);
    }
  }

  private SignalServiceAttachmentPointer uploadAttachmentV2(SignalServiceAttachmentStream attachment, byte[] attachmentKey, PushAttachmentData attachmentData)
      throws NonSuccessfulResponseCodeException, PushNetworkException, MalformedResponseException
  {
    AttachmentV2UploadAttributes       v2UploadAttributes = null;

    Log.d(TAG, "Using pipe to retrieve attachment upload attributes...");
    try {
      v2UploadAttributes = new AttachmentService.AttachmentAttributesResponseProcessor<>(attachmentService.getAttachmentV2UploadAttributes().blockingGet()).getResultOrThrow();
    } catch (WebSocketUnavailableException e) {
      Log.w(TAG, "[uploadAttachmentV2] Pipe unavailable, falling back... (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
    } catch (IOException e) {
      Log.w(TAG, "Failed to retrieve attachment upload attributes using pipe. Falling back...");
    }

    if (v2UploadAttributes == null) {
      Log.d(TAG, "Not using pipe to retrieve attachment upload attributes...");
      v2UploadAttributes = socket.getAttachmentV2UploadAttributes();
    }

    Pair<Long, byte[]> attachmentIdAndDigest = socket.uploadAttachment(attachmentData, v2UploadAttributes);

    return new SignalServiceAttachmentPointer(0,
                                              new SignalServiceAttachmentRemoteId(attachmentIdAndDigest.first()),
                                              attachment.getContentType(),
                                              attachmentKey,
                                              Optional.of(Util.toIntExact(attachment.getLength())),
                                              attachment.getPreview(),
                                              attachment.getWidth(), attachment.getHeight(),
                                              Optional.of(attachmentIdAndDigest.second()),
                                              attachment.getFileName(),
                                              attachment.getVoiceNote(),
                                              attachment.isBorderless(),
                                              attachment.isGif(),
                                              attachment.getCaption(),
                                              attachment.getBlurHash(),
                                              attachment.getUploadTimestamp());
  }

  public ResumableUploadSpec getResumableUploadSpec() throws IOException {
    long                         start              = System.currentTimeMillis();
    AttachmentV3UploadAttributes v3UploadAttributes = null;

    Log.d(TAG, "Using pipe to retrieve attachment upload attributes...");
    try {
      v3UploadAttributes = new AttachmentService.AttachmentAttributesResponseProcessor<>(attachmentService.getAttachmentV3UploadAttributes().blockingGet()).getResultOrThrow();
    } catch (WebSocketUnavailableException e) {
      Log.w(TAG, "[getResumableUploadSpec] Pipe unavailable, falling back... (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
    } catch (IOException e) {
      Log.w(TAG, "Failed to retrieve attachment upload attributes using pipe. Falling back...");
    }
    
    long webSocket = System.currentTimeMillis() - start;

    if (v3UploadAttributes == null) {
      Log.d(TAG, "Not using pipe to retrieve attachment upload attributes...");
      v3UploadAttributes = socket.getAttachmentV3UploadAttributes();
    }

    long                rest = System.currentTimeMillis() - start;
    ResumableUploadSpec spec = socket.getResumableUploadSpec(v3UploadAttributes);
    long                end  = System.currentTimeMillis() - start;

    Log.d(TAG, "[getResumableUploadSpec] webSocket: " + webSocket + " rest: " + rest + " end: " + end);

    return spec;
  }

  private SignalServiceAttachmentPointer uploadAttachmentV3(SignalServiceAttachmentStream attachment, byte[] attachmentKey, PushAttachmentData attachmentData) throws IOException {
    byte[] digest = socket.uploadAttachment(attachmentData);
    return new SignalServiceAttachmentPointer(attachmentData.getResumableUploadSpec().getCdnNumber(),
                                              new SignalServiceAttachmentRemoteId(attachmentData.getResumableUploadSpec().getCdnKey()),
                                              attachment.getContentType(),
                                              attachmentKey,
                                              Optional.of(Util.toIntExact(attachment.getLength())),
                                              attachment.getPreview(),
                                              attachment.getWidth(),
                                              attachment.getHeight(),
                                              Optional.of(digest),
                                              attachment.getFileName(),
                                              attachment.getVoiceNote(),
                                              attachment.isBorderless(),
                                              attachment.isGif(),
                                              attachment.getCaption(),
                                              attachment.getBlurHash(),
                                              attachment.getUploadTimestamp());
  }

  private SendMessageResult sendVerifiedSyncMessage(VerifiedMessage message)
      throws IOException, UntrustedIdentityException
  {
    byte[] nullMessageBody = DataMessage.newBuilder()
                                        .setBody(Base64.encodeBytes(Util.getRandomLengthBytes(140)))
                                        .build()
                                        .toByteArray();

    NullMessage nullMessage = NullMessage.newBuilder()
                                         .setPadding(ByteString.copyFrom(nullMessageBody))
                                         .build();

    Content     content     = Content.newBuilder()
                                     .setNullMessage(nullMessage)
                                     .build();

    EnvelopeContent envelopeContent = EnvelopeContent.encrypted(content, ContentHint.IMPLICIT, Optional.absent());

    SendMessageResult result = sendMessage(message.getDestination(), Optional.absent(), message.getTimestamp(), envelopeContent, false, null);

    if (result.getSuccess().isNeedsSync()) {
      Content         syncMessage        = createMultiDeviceVerifiedContent(message, nullMessage.toByteArray());
      EnvelopeContent syncMessageContent = EnvelopeContent.encrypted(syncMessage, ContentHint.IMPLICIT, Optional.absent());

      sendMessage(localAddress, Optional.absent(), message.getTimestamp(), syncMessageContent, false, null);
    }

    return result;
  }

  public SendMessageResult sendNullMessage(SignalServiceAddress address, Optional<UnidentifiedAccessPair> unidentifiedAccess)
      throws UntrustedIdentityException, IOException
  {
    byte[] nullMessageBody = DataMessage.newBuilder()
                                        .setBody(Base64.encodeBytes(Util.getRandomLengthBytes(140)))
                                        .build()
                                        .toByteArray();

    NullMessage nullMessage = NullMessage.newBuilder()
                                         .setPadding(ByteString.copyFrom(nullMessageBody))
                                         .build();

    Content     content     = Content.newBuilder()
                                     .setNullMessage(nullMessage)
                                     .build();

    EnvelopeContent envelopeContent = EnvelopeContent.encrypted(content, ContentHint.IMPLICIT, Optional.absent());

    return sendMessage(address, getTargetUnidentifiedAccess(unidentifiedAccess), System.currentTimeMillis(), envelopeContent, false, null);
  }

  private Content createTypingContent(SignalServiceTypingMessage message) {
    Content.Builder       container = Content.newBuilder();
    TypingMessage.Builder builder   = TypingMessage.newBuilder();

    builder.setTimestamp(message.getTimestamp());

    if      (message.isTypingStarted()) builder.setAction(TypingMessage.Action.STARTED);
    else if (message.isTypingStopped()) builder.setAction(TypingMessage.Action.STOPPED);
    else                                throw new IllegalArgumentException("Unknown typing indicator");

    if (message.getGroupId().isPresent()) {
      builder.setGroupId(ByteString.copyFrom(message.getGroupId().get()));
    }

    return container.setTypingMessage(builder).build();
  }

  private Content createStoryContent(SignalServiceStoryMessage message) throws IOException {
    Content.Builder      container = Content.newBuilder();
    StoryMessage.Builder builder   = StoryMessage.newBuilder();

    if (message.getProfileKey().isPresent()) {
      builder.setProfileKey(ByteString.copyFrom(message.getProfileKey().get()));
    }

    if (message.getGroupContext().isPresent()) {
      builder.setGroup(createGroupContent(message.getGroupContext().get()));
    }

    if (message.getFileAttachment().isPresent()) {
      if (message.getFileAttachment().get().isStream()) {
        builder.setFileAttachment(createAttachmentPointer(message.getFileAttachment().get().asStream()));
      } else {
        builder.setFileAttachment(createAttachmentPointer(message.getFileAttachment().get().asPointer()));
      }
    }

    if (message.getTextAttachment().isPresent()) {
      builder.setTextAttachment(createTextAttachment(message.getTextAttachment().get()));
    }

    builder.setAllowsReplies(message.getAllowsReplies().or(true));

    return container.setStoryMessage(builder).build();
  }

  private Content createReceiptContent(SignalServiceReceiptMessage message) {
    Content.Builder        container = Content.newBuilder();
    ReceiptMessage.Builder builder   = ReceiptMessage.newBuilder();

    for (long timestamp : message.getTimestamps()) {
      builder.addTimestamp(timestamp);
    }

    if      (message.isDeliveryReceipt()) builder.setType(ReceiptMessage.Type.DELIVERY);
    else if (message.isReadReceipt())     builder.setType(ReceiptMessage.Type.READ);
    else if (message.isViewedReceipt())   builder.setType(ReceiptMessage.Type.VIEWED);

    return container.setReceiptMessage(builder).build();
  }

  private Content createMessageContent(SignalServiceDataMessage message) throws IOException {
    Content.Builder         container = Content.newBuilder();
    DataMessage.Builder     builder   = DataMessage.newBuilder();
    List<AttachmentPointer> pointers  = createAttachmentPointers(message.getAttachments());

    if (!pointers.isEmpty()) {
      builder.addAllAttachments(pointers);

      for (AttachmentPointer pointer : pointers) {
        if (pointer.getAttachmentIdentifierCase() == AttachmentPointer.AttachmentIdentifierCase.CDNKEY || pointer.getCdnNumber() != 0) {
          builder.setRequiredProtocolVersion(Math.max(DataMessage.ProtocolVersion.CDN_SELECTOR_ATTACHMENTS_VALUE, builder.getRequiredProtocolVersion()));
          break;
        }
      }
    }

    if (message.getBody().isPresent()) {
      builder.setBody(message.getBody().get());
    }

    if (message.getGroupContext().isPresent()) {
      SignalServiceGroupContext groupContext = message.getGroupContext().get();
      if (groupContext.getGroupV1().isPresent()) {
        builder.setGroup(createGroupContent(groupContext.getGroupV1().get()));
      }

      if (groupContext.getGroupV2().isPresent()) {
        builder.setGroupV2(createGroupContent(groupContext.getGroupV2().get()));
      }
    }

    if (message.isEndSession()) {
      builder.setFlags(DataMessage.Flags.END_SESSION_VALUE);
    }

    if (message.isExpirationUpdate()) {
      builder.setFlags(DataMessage.Flags.EXPIRATION_TIMER_UPDATE_VALUE);
    }

    if (message.isProfileKeyUpdate()) {
      builder.setFlags(DataMessage.Flags.PROFILE_KEY_UPDATE_VALUE);
    }

    if (message.getExpiresInSeconds() > 0) {
      builder.setExpireTimer(message.getExpiresInSeconds());
    }

    if (message.getProfileKey().isPresent()) {
      builder.setProfileKey(ByteString.copyFrom(message.getProfileKey().get()));
    }

    if (message.getQuote().isPresent()) {
      DataMessage.Quote.Builder quoteBuilder = DataMessage.Quote.newBuilder()
                                                                .setId(message.getQuote().get().getId())
                                                                .setText(message.getQuote().get().getText())
                                                                .setAuthorUuid(message.getQuote().get().getAuthor().getServiceId().toString());

      if (!message.getQuote().get().getMentions().isEmpty()) {
        for (SignalServiceDataMessage.Mention mention : message.getQuote().get().getMentions()) {
          quoteBuilder.addBodyRanges(DataMessage.BodyRange.newBuilder()
                                                          .setStart(mention.getStart())
                                                          .setLength(mention.getLength())
                                                          .setMentionUuid(mention.getServiceId().toString()));
        }

        builder.setRequiredProtocolVersion(Math.max(DataMessage.ProtocolVersion.MENTIONS_VALUE, builder.getRequiredProtocolVersion()));
      }

      for (SignalServiceDataMessage.Quote.QuotedAttachment attachment : message.getQuote().get().getAttachments()) {
        DataMessage.Quote.QuotedAttachment.Builder quotedAttachment = DataMessage.Quote.QuotedAttachment.newBuilder();

        quotedAttachment.setContentType(attachment.getContentType());

        if (attachment.getFileName() != null) {
          quotedAttachment.setFileName(attachment.getFileName());
        }

        if (attachment.getThumbnail() != null) {
          quotedAttachment.setThumbnail(createAttachmentPointer(attachment.getThumbnail().asStream()));
        }

        quoteBuilder.addAttachments(quotedAttachment);
      }

      builder.setQuote(quoteBuilder);
    }

    if (message.getSharedContacts().isPresent()) {
      builder.addAllContact(createSharedContactContent(message.getSharedContacts().get()));
    }

    if (message.getPreviews().isPresent()) {
      for (SignalServicePreview preview : message.getPreviews().get()) {
        builder.addPreview(createPreview(preview));
      }
    }

    if (message.getMentions().isPresent()) {
      for (SignalServiceDataMessage.Mention mention : message.getMentions().get()) {
        builder.addBodyRanges(DataMessage.BodyRange.newBuilder()
                                                   .setStart(mention.getStart())
                                                   .setLength(mention.getLength())
                                                   .setMentionUuid(mention.getServiceId().toString()));
      }
      builder.setRequiredProtocolVersion(Math.max(DataMessage.ProtocolVersion.MENTIONS_VALUE, builder.getRequiredProtocolVersion()));
    }

    if (message.getSticker().isPresent()) {
      DataMessage.Sticker.Builder stickerBuilder = DataMessage.Sticker.newBuilder();

      stickerBuilder.setPackId(ByteString.copyFrom(message.getSticker().get().getPackId()));
      stickerBuilder.setPackKey(ByteString.copyFrom(message.getSticker().get().getPackKey()));
      stickerBuilder.setStickerId(message.getSticker().get().getStickerId());

      if (message.getSticker().get().getEmoji() != null) {
        stickerBuilder.setEmoji(message.getSticker().get().getEmoji());
      }

      if (message.getSticker().get().getAttachment().isStream()) {
        stickerBuilder.setData(createAttachmentPointer(message.getSticker().get().getAttachment().asStream()));
      } else {
        stickerBuilder.setData(createAttachmentPointer(message.getSticker().get().getAttachment().asPointer()));
      }

      builder.setSticker(stickerBuilder.build());
    }

    if (message.isViewOnce()) {
      builder.setIsViewOnce(message.isViewOnce());
      builder.setRequiredProtocolVersion(Math.max(DataMessage.ProtocolVersion.VIEW_ONCE_VIDEO_VALUE, builder.getRequiredProtocolVersion()));
    }

    if (message.getReaction().isPresent()) {
      DataMessage.Reaction.Builder reactionBuilder = DataMessage.Reaction.newBuilder()
                                                                         .setEmoji(message.getReaction().get().getEmoji())
                                                                         .setRemove(message.getReaction().get().isRemove())
                                                                         .setTargetSentTimestamp(message.getReaction().get().getTargetSentTimestamp())
                                                                         .setTargetAuthorUuid(message.getReaction().get().getTargetAuthor().getServiceId().toString());

      builder.setReaction(reactionBuilder.build());
      builder.setRequiredProtocolVersion(Math.max(DataMessage.ProtocolVersion.REACTIONS_VALUE, builder.getRequiredProtocolVersion()));
    }

    if (message.getRemoteDelete().isPresent()) {
      DataMessage.Delete delete = DataMessage.Delete.newBuilder()
                                                    .setTargetSentTimestamp(message.getRemoteDelete().get().getTargetSentTimestamp())
                                                    .build();
      builder.setDelete(delete);
    }

    if (message.getGroupCallUpdate().isPresent()) {
      builder.setGroupCallUpdate(DataMessage.GroupCallUpdate.newBuilder().setEraId(message.getGroupCallUpdate().get().getEraId()));
    }

    if (message.getPayment().isPresent()) {
      SignalServiceDataMessage.Payment payment = message.getPayment().get();

      if (payment.getPaymentNotification().isPresent()) {
        SignalServiceDataMessage.PaymentNotification        paymentNotification = payment.getPaymentNotification().get();
        DataMessage.Payment.Notification.MobileCoin.Builder mobileCoinPayment   = DataMessage.Payment.Notification.MobileCoin.newBuilder().setReceipt(ByteString.copyFrom(paymentNotification.getReceipt()));
        DataMessage.Payment.Notification.Builder            paymentBuilder      = DataMessage.Payment.Notification.newBuilder()
                                                                                                                  .setNote(paymentNotification.getNote())
                                                                                                                  .setMobileCoin(mobileCoinPayment);

        builder.setPayment(DataMessage.Payment.newBuilder().setNotification(paymentBuilder));
        builder.setRequiredProtocolVersion(Math.max(DataMessage.ProtocolVersion.PAYMENTS_VALUE, builder.getRequiredProtocolVersion()));
      }
    }

    if (message.getStoryContext().isPresent()) {
      SignalServiceDataMessage.StoryContext storyContext = message.getStoryContext().get();

      builder.setStoryContext(DataMessage.StoryContext.newBuilder()
                                                      .setAuthorUuid(storyContext.getAuthorServiceId().toString())
                                                      .setSentTimestamp(storyContext.getSentTimestamp()));
    }

    builder.setTimestamp(message.getTimestamp());

    return enforceMaxContentSize(container.setDataMessage(builder).build());
  }

  private Preview createPreview(SignalServicePreview preview) throws IOException {
    Preview.Builder previewBuilder = Preview.newBuilder()
                                            .setTitle(preview.getTitle())
                                            .setDescription(preview.getDescription())
                                            .setDate(preview.getDate())
                                            .setUrl(preview.getUrl());

    if (preview.getImage().isPresent()) {
      if (preview.getImage().get().isStream()) {
        previewBuilder.setImage(createAttachmentPointer(preview.getImage().get().asStream()));
      } else {
        previewBuilder.setImage(createAttachmentPointer(preview.getImage().get().asPointer()));
      }
    }

    return previewBuilder.build();
  }

  private Content createCallContent(SignalServiceCallMessage callMessage) {
    Content.Builder     container = Content.newBuilder();
    CallMessage.Builder builder   = CallMessage.newBuilder();

    if (callMessage.getOfferMessage().isPresent()) {
      OfferMessage offer = callMessage.getOfferMessage().get();
      CallMessage.Offer.Builder offerBuilder = CallMessage.Offer.newBuilder()
                                                                .setId(offer.getId())
                                                                .setType(offer.getType().getProtoType());

      if (offer.getOpaque() != null) {
        offerBuilder.setOpaque(ByteString.copyFrom(offer.getOpaque()));
      }

      if (offer.getSdp() != null) {
        offerBuilder.setSdp(offer.getSdp());
      }

      builder.setOffer(offerBuilder);
    } else if (callMessage.getAnswerMessage().isPresent()) {
      AnswerMessage answer = callMessage.getAnswerMessage().get();
      CallMessage.Answer.Builder answerBuilder = CallMessage.Answer.newBuilder()
                                                                   .setId(answer.getId());

      if (answer.getOpaque() != null) {
        answerBuilder.setOpaque(ByteString.copyFrom(answer.getOpaque()));
      }

      if (answer.getSdp() != null) {
        answerBuilder.setSdp(answer.getSdp());
      }

      builder.setAnswer(answerBuilder);
    } else if (callMessage.getIceUpdateMessages().isPresent()) {
      List<IceUpdateMessage> updates = callMessage.getIceUpdateMessages().get();

      for (IceUpdateMessage update : updates) {
        CallMessage.IceUpdate.Builder iceBuilder = CallMessage.IceUpdate.newBuilder()
                                                                        .setId(update.getId())
                                                                        .setMid("audio")
                                                                        .setLine(0);

        if (update.getOpaque() != null) {
          iceBuilder.setOpaque(ByteString.copyFrom(update.getOpaque()));
        }

        if (update.getSdp() != null) {
          iceBuilder.setSdp(update.getSdp());
        }

        builder.addIceUpdate(iceBuilder);
      }
    } else if (callMessage.getHangupMessage().isPresent()) {
      CallMessage.Hangup.Type    protoType        = callMessage.getHangupMessage().get().getType().getProtoType();
      CallMessage.Hangup.Builder builderForHangup = CallMessage.Hangup.newBuilder()
                                                                      .setType(protoType)
                                                                      .setId(callMessage.getHangupMessage().get().getId());

      if (protoType != CallMessage.Hangup.Type.HANGUP_NORMAL) {
        builderForHangup.setDeviceId(callMessage.getHangupMessage().get().getDeviceId());
      }

      if (callMessage.getHangupMessage().get().isLegacy()) {
        builder.setLegacyHangup(builderForHangup);
      } else {
        builder.setHangup(builderForHangup);
      }
    } else if (callMessage.getBusyMessage().isPresent()) {
      builder.setBusy(CallMessage.Busy.newBuilder().setId(callMessage.getBusyMessage().get().getId()));
    } else if (callMessage.getOpaqueMessage().isPresent()) {
      OpaqueMessage              opaqueMessage = callMessage.getOpaqueMessage().get();
      ByteString                 data          = ByteString.copyFrom(opaqueMessage.getOpaque());
      CallMessage.Opaque.Urgency urgency       = opaqueMessage.getUrgency().toProto();

      builder.setOpaque(CallMessage.Opaque.newBuilder().setData(data).setUrgency(urgency));
    }

    builder.setMultiRing(callMessage.isMultiRing());

    if (callMessage.getDestinationDeviceId().isPresent()) {
      builder.setDestinationDeviceId(callMessage.getDestinationDeviceId().get());
    }

    container.setCallMessage(builder);
    return container.build();
  }

  private Content createMultiDeviceContactsContent(SignalServiceAttachmentStream contacts, boolean complete) throws IOException {
    Content.Builder     container = Content.newBuilder();
    SyncMessage.Builder builder   = createSyncMessageBuilder();
    builder.setContacts(SyncMessage.Contacts.newBuilder()
                                            .setBlob(createAttachmentPointer(contacts))
                                            .setComplete(complete));

    return container.setSyncMessage(builder).build();
  }

  private Content createMultiDeviceGroupsContent(SignalServiceAttachmentStream groups) throws IOException {
    Content.Builder     container = Content.newBuilder();
    SyncMessage.Builder builder   = createSyncMessageBuilder();

    builder.setGroups(SyncMessage.Groups.newBuilder()
                                        .setBlob(createAttachmentPointer(groups)));

    return container.setSyncMessage(builder).build();
  }

  private Content createMultiDeviceSentTranscriptContent(SentTranscriptMessage transcript, boolean unidentifiedAccess) throws IOException {
    SignalServiceAddress address = transcript.getDestination().get();
    Content              content = createMessageContent(transcript.getMessage());
    SendMessageResult    result  = SendMessageResult.success(address, Collections.emptyList(), unidentifiedAccess, true, -1, Optional.of(content));

    return createMultiDeviceSentTranscriptContent(content,
                                                  Optional.of(address),
                                                  transcript.getTimestamp(),
                                                  Collections.singletonList(result),
                                                  false);
  }

  private Content createMultiDeviceSentTranscriptContent(Content content, Optional<SignalServiceAddress> recipient,
                                                         long timestamp, List<SendMessageResult> sendMessageResults,
                                                         boolean isRecipientUpdate)
  {
    Content.Builder          container   = Content.newBuilder();
    SyncMessage.Builder      syncMessage = createSyncMessageBuilder();
    SyncMessage.Sent.Builder sentMessage = SyncMessage.Sent.newBuilder();
    DataMessage              dataMessage = content.getDataMessage();

    sentMessage.setTimestamp(timestamp);
    sentMessage.setMessage(dataMessage);

    for (SendMessageResult result : sendMessageResults) {
      if (result.getSuccess() != null) {
        sentMessage.addUnidentifiedStatus(SyncMessage.Sent.UnidentifiedDeliveryStatus.newBuilder()
                                                                                     .setDestinationUuid(result.getAddress().getServiceId().toString())
                                                                                     .setUnidentified(result.getSuccess().isUnidentified())
                                                                                     .build());

      }
    }

    if (recipient.isPresent()) {
      sentMessage.setDestinationUuid(recipient.get().getServiceId().toString());
    }

    if (dataMessage.getExpireTimer() > 0) {
      sentMessage.setExpirationStartTimestamp(System.currentTimeMillis());
    }

    if (dataMessage.getIsViewOnce()) {
      dataMessage = dataMessage.toBuilder().clearAttachments().build();
      sentMessage.setMessage(dataMessage);
    }

    sentMessage.setIsRecipientUpdate(isRecipientUpdate);

    return container.setSyncMessage(syncMessage.setSent(sentMessage)).build();
  }

  private Content createMultiDeviceReadContent(List<ReadMessage> readMessages) {
    Content.Builder     container = Content.newBuilder();
    SyncMessage.Builder builder   = createSyncMessageBuilder();

    for (ReadMessage readMessage : readMessages) {
      builder.addRead(SyncMessage.Read.newBuilder()
                                      .setTimestamp(readMessage.getTimestamp())
                                      .setSenderUuid(readMessage.getSender().getServiceId().toString()));
    }

    return container.setSyncMessage(builder).build();
  }

  private Content createMultiDeviceViewedContent(List<ViewedMessage> readMessages) {
    Content.Builder     container = Content.newBuilder();
    SyncMessage.Builder builder   = createSyncMessageBuilder();

    for (ViewedMessage readMessage : readMessages) {
      builder.addViewed(SyncMessage.Viewed.newBuilder()
                                          .setTimestamp(readMessage.getTimestamp())
                                          .setSenderUuid(readMessage.getSender().getServiceId().toString()));
    }

    return container.setSyncMessage(builder).build();
  }

  private Content createMultiDeviceViewOnceOpenContent(ViewOnceOpenMessage readMessage) {
    Content.Builder                  container       = Content.newBuilder();
    SyncMessage.Builder              builder         = createSyncMessageBuilder();

    builder.setViewOnceOpen(SyncMessage.ViewOnceOpen.newBuilder()
                                                    .setTimestamp(readMessage.getTimestamp())
                                                    .setSenderUuid(readMessage.getSender().getServiceId().toString()));

    return container.setSyncMessage(builder).build();
  }

  private Content createMultiDeviceBlockedContent(BlockedListMessage blocked) {
    Content.Builder             container      = Content.newBuilder();
    SyncMessage.Builder         syncMessage    = createSyncMessageBuilder();
    SyncMessage.Blocked.Builder blockedMessage = SyncMessage.Blocked.newBuilder();

    for (SignalServiceAddress address : blocked.getAddresses()) {
      blockedMessage.addUuids(address.getServiceId().toString());
      if (address.getNumber().isPresent()) {
        blockedMessage.addNumbers(address.getNumber().get());
      }
    }

    for (byte[] groupId : blocked.getGroupIds()) {
      blockedMessage.addGroupIds(ByteString.copyFrom(groupId));
    }

    return container.setSyncMessage(syncMessage.setBlocked(blockedMessage)).build();
  }

  private Content createMultiDeviceConfigurationContent(ConfigurationMessage configuration) {
    Content.Builder                   container            = Content.newBuilder();
    SyncMessage.Builder               syncMessage          = createSyncMessageBuilder();
    SyncMessage.Configuration.Builder configurationMessage = SyncMessage.Configuration.newBuilder();

    if (configuration.getReadReceipts().isPresent()) {
      configurationMessage.setReadReceipts(configuration.getReadReceipts().get());
    }

    if (configuration.getUnidentifiedDeliveryIndicators().isPresent()) {
      configurationMessage.setUnidentifiedDeliveryIndicators(configuration.getUnidentifiedDeliveryIndicators().get());
    }

    if (configuration.getTypingIndicators().isPresent()) {
      configurationMessage.setTypingIndicators(configuration.getTypingIndicators().get());
    }

    if (configuration.getLinkPreviews().isPresent()) {
      configurationMessage.setLinkPreviews(configuration.getLinkPreviews().get());
    }

    configurationMessage.setProvisioningVersion(ProvisioningProtos.ProvisioningVersion.CURRENT_VALUE);

    return container.setSyncMessage(syncMessage.setConfiguration(configurationMessage)).build();
  }

  private Content createMultiDeviceStickerPackOperationContent(List<StickerPackOperationMessage> stickerPackOperations) {
    Content.Builder     container   = Content.newBuilder();
    SyncMessage.Builder syncMessage = createSyncMessageBuilder();

    for (StickerPackOperationMessage stickerPackOperation : stickerPackOperations) {
      SyncMessage.StickerPackOperation.Builder builder = SyncMessage.StickerPackOperation.newBuilder();

      if (stickerPackOperation.getPackId().isPresent()) {
        builder.setPackId(ByteString.copyFrom(stickerPackOperation.getPackId().get()));
      }

      if (stickerPackOperation.getPackKey().isPresent()) {
        builder.setPackKey(ByteString.copyFrom(stickerPackOperation.getPackKey().get()));
      }

      if (stickerPackOperation.getType().isPresent()) {
        switch (stickerPackOperation.getType().get()) {
          case INSTALL: builder.setType(SyncMessage.StickerPackOperation.Type.INSTALL); break;
          case REMOVE:  builder.setType(SyncMessage.StickerPackOperation.Type.REMOVE); break;
        }
      }

      syncMessage.addStickerPackOperation(builder);
    }

    return container.setSyncMessage(syncMessage).build();
  }

  private Content createMultiDeviceFetchTypeContent(SignalServiceSyncMessage.FetchType fetchType) {
    Content.Builder                 container    = Content.newBuilder();
    SyncMessage.Builder             syncMessage  = createSyncMessageBuilder();
    SyncMessage.FetchLatest.Builder fetchMessage = SyncMessage.FetchLatest.newBuilder();

    switch (fetchType) {
      case LOCAL_PROFILE:
        fetchMessage.setType(SyncMessage.FetchLatest.Type.LOCAL_PROFILE);
        break;
      case STORAGE_MANIFEST:
        fetchMessage.setType(SyncMessage.FetchLatest.Type.STORAGE_MANIFEST);
        break;
      case SUBSCRIPTION_STATUS:
       fetchMessage.setType(SyncMessage.FetchLatest.Type.SUBSCRIPTION_STATUS);
        break;
      default:
        Log.w(TAG, "Unknown fetch type!");
        break;
    }

    return container.setSyncMessage(syncMessage.setFetchLatest(fetchMessage)).build();
  }

  private Content createMultiDeviceMessageRequestResponseContent(MessageRequestResponseMessage message) {
    Content.Builder container = Content.newBuilder();
    SyncMessage.Builder syncMessage = createSyncMessageBuilder();
    SyncMessage.MessageRequestResponse.Builder responseMessage = SyncMessage.MessageRequestResponse.newBuilder();

    if (message.getGroupId().isPresent()) {
      responseMessage.setGroupId(ByteString.copyFrom(message.getGroupId().get()));
    }

    if (message.getPerson().isPresent()) {
      responseMessage.setThreadUuid(message.getPerson().get().getServiceId().toString());
    }

    switch (message.getType()) {
      case ACCEPT:
        responseMessage.setType(SyncMessage.MessageRequestResponse.Type.ACCEPT);
        break;
      case DELETE:
        responseMessage.setType(SyncMessage.MessageRequestResponse.Type.DELETE);
        break;
      case BLOCK:
        responseMessage.setType(SyncMessage.MessageRequestResponse.Type.BLOCK);
        break;
      case BLOCK_AND_DELETE:
        responseMessage.setType(SyncMessage.MessageRequestResponse.Type.BLOCK_AND_DELETE);
        break;
      default:
        Log.w(TAG, "Unknown type!");
        responseMessage.setType(SyncMessage.MessageRequestResponse.Type.UNKNOWN);
        break;
    }

    syncMessage.setMessageRequestResponse(responseMessage);

    return container.setSyncMessage(syncMessage).build();
  }

  private Content createMultiDeviceOutgoingPaymentContent(OutgoingPaymentMessage message) {
    Content.Builder                     container      = Content.newBuilder();
    SyncMessage.Builder                 syncMessage    = createSyncMessageBuilder();
    SyncMessage.OutgoingPayment.Builder paymentMessage = SyncMessage.OutgoingPayment.newBuilder();

    if (message.getRecipient().isPresent()) {
      paymentMessage.setRecipientUuid(message.getRecipient().get().getServiceId().toString());
    }

    if (message.getNote().isPresent()) {
      paymentMessage.setNote(message.getNote().get());
    }

    try {
      SyncMessage.OutgoingPayment.MobileCoin.Builder mobileCoinBuilder = SyncMessage.OutgoingPayment.MobileCoin.newBuilder();

      if (message.getAddress().isPresent()) {
        mobileCoinBuilder.setRecipientAddress(ByteString.copyFrom(message.getAddress().get()));
      }
      mobileCoinBuilder.setAmountPicoMob(Uint64Util.bigIntegerToUInt64(message.getAmount().toPicoMobBigInteger()))
                       .setFeePicoMob(Uint64Util.bigIntegerToUInt64(message.getFee().toPicoMobBigInteger()))
                       .setReceipt(message.getReceipt())
                       .setLedgerBlockTimestamp(message.getBlockTimestamp())
                       .setLedgerBlockIndex(message.getBlockIndex())
                       .addAllOutputPublicKeys(message.getPublicKeys())
                       .addAllSpentKeyImages(message.getKeyImages());

      paymentMessage.setMobileCoin(mobileCoinBuilder);
    } catch (Uint64RangeException e) {
      throw new AssertionError(e);
    }

    syncMessage.setOutgoingPayment(paymentMessage);

    return container.setSyncMessage(syncMessage).build();
  }

  private Content createMultiDeviceSyncKeysContent(KeysMessage keysMessage) {
    Content.Builder          container   = Content.newBuilder();
    SyncMessage.Builder      syncMessage = createSyncMessageBuilder();
    SyncMessage.Keys.Builder builder     = SyncMessage.Keys.newBuilder();

    if (keysMessage.getStorageService().isPresent()) {
      builder.setStorageService(ByteString.copyFrom(keysMessage.getStorageService().get().serialize()));
    } else {
      Log.w(TAG, "Invalid keys message!");
    }

    return container.setSyncMessage(syncMessage.setKeys(builder)).build();
  }

  private Content createMultiDeviceVerifiedContent(VerifiedMessage verifiedMessage, byte[] nullMessage) {
    Content.Builder     container              = Content.newBuilder();
    SyncMessage.Builder syncMessage            = createSyncMessageBuilder();
    Verified.Builder    verifiedMessageBuilder = Verified.newBuilder();

    verifiedMessageBuilder.setNullMessage(ByteString.copyFrom(nullMessage));
    verifiedMessageBuilder.setIdentityKey(ByteString.copyFrom(verifiedMessage.getIdentityKey().serialize()));
    verifiedMessageBuilder.setDestinationUuid(verifiedMessage.getDestination().getServiceId().toString());


    switch(verifiedMessage.getVerified()) {
      case DEFAULT:    verifiedMessageBuilder.setState(Verified.State.DEFAULT);    break;
      case VERIFIED:   verifiedMessageBuilder.setState(Verified.State.VERIFIED);   break;
      case UNVERIFIED: verifiedMessageBuilder.setState(Verified.State.UNVERIFIED); break;
      default:         throw new AssertionError("Unknown: " + verifiedMessage.getVerified());
    }

    syncMessage.setVerified(verifiedMessageBuilder);
    return container.setSyncMessage(syncMessage).build();
  }

  private Content createRequestContent(SyncMessage.Request request) throws IOException {
    if (localDeviceId == SignalServiceAddress.DEFAULT_DEVICE_ID) {
      throw new IOException("Sync requests should only be sent from a linked device");
    }

    Content.Builder     container = Content.newBuilder();
    SyncMessage.Builder builder   = SyncMessage.newBuilder().setRequest(request);

    return container.setSyncMessage(builder).build();
  }

  private SyncMessage.Builder createSyncMessageBuilder() {
    SecureRandom random  = new SecureRandom();
    byte[]       padding = Util.getRandomLengthBytes(512);
    random.nextBytes(padding);

    SyncMessage.Builder builder = SyncMessage.newBuilder();
    builder.setPadding(ByteString.copyFrom(padding));

    return builder;
  }

  private GroupContext createGroupContent(SignalServiceGroup group) throws IOException {
    GroupContext.Builder builder = GroupContext.newBuilder();
    builder.setId(ByteString.copyFrom(group.getGroupId()));

    if (group.getType() != SignalServiceGroup.Type.DELIVER) {
      if      (group.getType() == SignalServiceGroup.Type.UPDATE)       builder.setType(GroupContext.Type.UPDATE);
      else if (group.getType() == SignalServiceGroup.Type.QUIT)         builder.setType(GroupContext.Type.QUIT);
      else if (group.getType() == SignalServiceGroup.Type.REQUEST_INFO) builder.setType(GroupContext.Type.REQUEST_INFO);
      else                                                              throw new AssertionError("Unknown type: " + group.getType());

      if (group.getName().isPresent()) {
        builder.setName(group.getName().get());
      }

      if (group.getMembers().isPresent()) {
        for (SignalServiceAddress address : group.getMembers().get()) {
          if (address.getNumber().isPresent()) {
            builder.addMembersE164(address.getNumber().get());

            GroupContext.Member.Builder memberBuilder = GroupContext.Member.newBuilder();
            memberBuilder.setE164(address.getNumber().get());

            builder.addMembers(memberBuilder.build());
          }
        }
      }

      if (group.getAvatar().isPresent()) {
        if (group.getAvatar().get().isStream()) {
          builder.setAvatar(createAttachmentPointer(group.getAvatar().get().asStream()));
        } else {
          builder.setAvatar(createAttachmentPointer(group.getAvatar().get().asPointer()));
        }
      }
    } else {
      builder.setType(GroupContext.Type.DELIVER);
    }

    return builder.build();
  }

  private static GroupContextV2 createGroupContent(SignalServiceGroupV2 group) {
    GroupContextV2.Builder builder = GroupContextV2.newBuilder()
                                                   .setMasterKey(ByteString.copyFrom(group.getMasterKey().serialize()))
                                                   .setRevision(group.getRevision());


    byte[] signedGroupChange = group.getSignedGroupChange();
    if (signedGroupChange != null && signedGroupChange.length <= 2048) {
      builder.setGroupChange(ByteString.copyFrom(signedGroupChange));
    }

    return builder.build();
  }

  private List<DataMessage.Contact> createSharedContactContent(List<SharedContact> contacts) throws IOException {
    List<DataMessage.Contact> results = new LinkedList<>();

    for (SharedContact contact : contacts) {
      DataMessage.Contact.Name.Builder nameBuilder    = DataMessage.Contact.Name.newBuilder();

      if (contact.getName().getFamily().isPresent())  nameBuilder.setFamilyName(contact.getName().getFamily().get());
      if (contact.getName().getGiven().isPresent())   nameBuilder.setGivenName(contact.getName().getGiven().get());
      if (contact.getName().getMiddle().isPresent())  nameBuilder.setMiddleName(contact.getName().getMiddle().get());
      if (contact.getName().getPrefix().isPresent())  nameBuilder.setPrefix(contact.getName().getPrefix().get());
      if (contact.getName().getSuffix().isPresent())  nameBuilder.setSuffix(contact.getName().getSuffix().get());
      if (contact.getName().getDisplay().isPresent()) nameBuilder.setDisplayName(contact.getName().getDisplay().get());

      DataMessage.Contact.Builder contactBuilder = DataMessage.Contact.newBuilder()
                                                                      .setName(nameBuilder);

      if (contact.getAddress().isPresent()) {
        for (SharedContact.PostalAddress address : contact.getAddress().get()) {
          DataMessage.Contact.PostalAddress.Builder addressBuilder = DataMessage.Contact.PostalAddress.newBuilder();

          switch (address.getType()) {
            case HOME:   addressBuilder.setType(DataMessage.Contact.PostalAddress.Type.HOME); break;
            case WORK:   addressBuilder.setType(DataMessage.Contact.PostalAddress.Type.WORK); break;
            case CUSTOM: addressBuilder.setType(DataMessage.Contact.PostalAddress.Type.CUSTOM); break;
            default:     throw new AssertionError("Unknown type: " + address.getType());
          }

          if (address.getCity().isPresent())         addressBuilder.setCity(address.getCity().get());
          if (address.getCountry().isPresent())      addressBuilder.setCountry(address.getCountry().get());
          if (address.getLabel().isPresent())        addressBuilder.setLabel(address.getLabel().get());
          if (address.getNeighborhood().isPresent()) addressBuilder.setNeighborhood(address.getNeighborhood().get());
          if (address.getPobox().isPresent())        addressBuilder.setPobox(address.getPobox().get());
          if (address.getPostcode().isPresent())     addressBuilder.setPostcode(address.getPostcode().get());
          if (address.getRegion().isPresent())       addressBuilder.setRegion(address.getRegion().get());
          if (address.getStreet().isPresent())       addressBuilder.setStreet(address.getStreet().get());

          contactBuilder.addAddress(addressBuilder);
        }
      }

      if (contact.getEmail().isPresent()) {
        for (SharedContact.Email email : contact.getEmail().get()) {
          DataMessage.Contact.Email.Builder emailBuilder = DataMessage.Contact.Email.newBuilder()
                                                                                    .setValue(email.getValue());

          switch (email.getType()) {
            case HOME:   emailBuilder.setType(DataMessage.Contact.Email.Type.HOME);   break;
            case WORK:   emailBuilder.setType(DataMessage.Contact.Email.Type.WORK);   break;
            case MOBILE: emailBuilder.setType(DataMessage.Contact.Email.Type.MOBILE); break;
            case CUSTOM: emailBuilder.setType(DataMessage.Contact.Email.Type.CUSTOM); break;
            default:     throw new AssertionError("Unknown type: " + email.getType());
          }

          if (email.getLabel().isPresent()) emailBuilder.setLabel(email.getLabel().get());

          contactBuilder.addEmail(emailBuilder);
        }
      }

      if (contact.getPhone().isPresent()) {
        for (SharedContact.Phone phone : contact.getPhone().get()) {
          DataMessage.Contact.Phone.Builder phoneBuilder = DataMessage.Contact.Phone.newBuilder()
                                                                                    .setValue(phone.getValue());

          switch (phone.getType()) {
            case HOME:   phoneBuilder.setType(DataMessage.Contact.Phone.Type.HOME);   break;
            case WORK:   phoneBuilder.setType(DataMessage.Contact.Phone.Type.WORK);   break;
            case MOBILE: phoneBuilder.setType(DataMessage.Contact.Phone.Type.MOBILE); break;
            case CUSTOM: phoneBuilder.setType(DataMessage.Contact.Phone.Type.CUSTOM); break;
            default:     throw new AssertionError("Unknown type: " + phone.getType());
          }

          if (phone.getLabel().isPresent()) phoneBuilder.setLabel(phone.getLabel().get());

          contactBuilder.addNumber(phoneBuilder);
        }
      }

      if (contact.getAvatar().isPresent()) {
        AttachmentPointer pointer = contact.getAvatar().get().getAttachment().isStream() ? createAttachmentPointer(contact.getAvatar().get().getAttachment().asStream())
                                                                                         : createAttachmentPointer(contact.getAvatar().get().getAttachment().asPointer());
        contactBuilder.setAvatar(DataMessage.Contact.Avatar.newBuilder()
                                                           .setAvatar(pointer)
                                                           .setIsProfile(contact.getAvatar().get().isProfile()));
      }

      if (contact.getOrganization().isPresent()) {
        contactBuilder.setOrganization(contact.getOrganization().get());
      }

      results.add(contactBuilder.build());
    }

    return results;
  }

  private SignalServiceSyncMessage createSelfSendSyncMessage(SignalServiceDataMessage message) {
    SentTranscriptMessage transcript = new SentTranscriptMessage(Optional.of(localAddress),
                                                                 message.getTimestamp(),
                                                                 message,
                                                                 message.getExpiresInSeconds(),
                                                                 Collections.singletonMap(localAddress, false),
                                                                 false);
    return SignalServiceSyncMessage.forSentTranscript(transcript);
  }

  private List<SendMessageResult> sendMessage(List<SignalServiceAddress>         recipients,
                                              List<Optional<UnidentifiedAccess>> unidentifiedAccess,
                                              long                               timestamp,
                                              EnvelopeContent                    content,
                                              boolean                            online,
                                              PartialSendCompleteListener        partialListener,
                                              CancelationSignal                  cancelationSignal)
      throws IOException
  {
    Log.d(TAG, "[" + timestamp + "] Sending to " + recipients.size() + " recipients.");
    enforceMaxContentSize(content);

    long                                   startTime                  = System.currentTimeMillis();
    List<Future<SendMessageResult>>        futureResults              = new LinkedList<>();
    Iterator<SignalServiceAddress>         recipientIterator          = recipients.iterator();
    Iterator<Optional<UnidentifiedAccess>> unidentifiedAccessIterator = unidentifiedAccess.iterator();

    while (recipientIterator.hasNext()) {
      SignalServiceAddress         recipient = recipientIterator.next();
      Optional<UnidentifiedAccess> access    = unidentifiedAccessIterator.next();
      futureResults.add(executor.submit(() -> {
        SendMessageResult result = sendMessage(recipient, access, timestamp, content, online, cancelationSignal);
        if (partialListener != null) {
          partialListener.onPartialSendComplete(result);
        }
        return result;
      }));
    }

    List<SendMessageResult> results = new ArrayList<>(futureResults.size());
    recipientIterator = recipients.iterator();

    for (Future<SendMessageResult> futureResult : futureResults) {
      SignalServiceAddress recipient = recipientIterator.next();
      try {
        results.add(futureResult.get());
      } catch (ExecutionException e) {
        if (e.getCause() instanceof UntrustedIdentityException) {
          Log.w(TAG, e);
          results.add(SendMessageResult.identityFailure(recipient, ((UntrustedIdentityException) e.getCause()).getIdentityKey()));
        } else if (e.getCause() instanceof UnregisteredUserException) {
          Log.w(TAG, "[" + timestamp + "] Found unregistered user.");
          results.add(SendMessageResult.unregisteredFailure(recipient));
        } else if (e.getCause() instanceof PushNetworkException) {
          Log.w(TAG, e);
          results.add(SendMessageResult.networkFailure(recipient));
        } else if (e.getCause() instanceof ServerRejectedException) {
          Log.w(TAG, e);
          throw ((ServerRejectedException) e.getCause());
        } else if (e.getCause() instanceof ProofRequiredException) {
          Log.w(TAG, e);
          results.add(SendMessageResult.proofRequiredFailure(recipient, (ProofRequiredException) e.getCause()));
        } else if (e.getCause() instanceof RateLimitException) {
          Log.w(TAG, e);
          results.add(SendMessageResult.rateLimitFailure(recipient, (RateLimitException) e.getCause()));
        } else {
          throw new IOException(e);
        }
      } catch (InterruptedException e) {
        throw new IOException(e);
      }
    }

    double sendsForAverage = 0;
    for (SendMessageResult result : results) {
      if (result.getSuccess() != null && result.getSuccess().getDuration() != -1) {
        sendsForAverage++;
      }
    }

    double average = 0;
    if (sendsForAverage > 0) {
      for (SendMessageResult result : results) {
        if (result.getSuccess() != null && result.getSuccess().getDuration() != -1) {
          average += result.getSuccess().getDuration() / sendsForAverage;
        }
      }
    }

    Log.d(TAG, "[" + timestamp + "] Completed send to " + recipients.size() + " recipients in " + (System.currentTimeMillis() - startTime) + " ms, with an average time of " + Math.round(average) + " ms per send.");
    return results;
  }

  private SendMessageResult sendMessage(SignalServiceAddress         recipient,
                                        Optional<UnidentifiedAccess> unidentifiedAccess,
                                        long                         timestamp,
                                        EnvelopeContent              content,
                                        boolean                      online,
                                        CancelationSignal            cancelationSignal)
      throws UntrustedIdentityException, IOException
  {
    enforceMaxContentSize(content);

    long startTime = System.currentTimeMillis();

    for (int i = 0; i < RETRY_COUNT; i++) {
      if (cancelationSignal != null && cancelationSignal.isCanceled()) {
        throw new CancelationException();
      }

      try {
        OutgoingPushMessageList messages = getEncryptedMessages(socket, recipient, unidentifiedAccess, timestamp, content, online);

        if (content.getContent().isPresent() && content.getContent().get().getSyncMessage() != null && content.getContent().get().getSyncMessage().hasSent()) {
          Log.d(TAG, "[sendMessage][" + timestamp + "] Sending a sent sync message to devices: " + messages.getDevices());
        } else if (content.getContent().isPresent() && content.getContent().get().hasSenderKeyDistributionMessage()) {
          Log.d(TAG, "[sendMessage][" + timestamp + "] Sending a SKDM to " + messages.getDestination() + " for devices: " + messages.getDevices());
        }

        if (cancelationSignal != null && cancelationSignal.isCanceled()) {
          throw new CancelationException();
        }

        if (!unidentifiedAccess.isPresent()) {
          try {
            SendMessageResponse response = new MessagingService.SendResponseProcessor<>(messagingService.send(messages, Optional.absent()).blockingGet()).getResultOrThrow();
            return SendMessageResult.success(recipient, messages.getDevices(), response.sentUnidentified(), response.getNeedsSync() || store.isMultiDevice(), System.currentTimeMillis() - startTime, content.getContent());
          } catch (InvalidUnidentifiedAccessHeaderException | UnregisteredUserException | MismatchedDevicesException | StaleDevicesException e) {
            // Non-technical failures shouldn't be retried with socket
            throw e;
          } catch (WebSocketUnavailableException e) {
            Log.i(TAG, "[sendMessage][" + timestamp + "] Pipe unavailable, falling back... (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
          } catch (IOException e) {
            Log.w(TAG, e);
            Log.w(TAG, "[sendMessage][" + timestamp + "] Pipe failed, falling back... (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
          }
        } else if (unidentifiedAccess.isPresent()) {
          try {
            SendMessageResponse response = new MessagingService.SendResponseProcessor<>(messagingService.send(messages, unidentifiedAccess).blockingGet()).getResultOrThrow();
            return SendMessageResult.success(recipient, messages.getDevices(), response.sentUnidentified(), response.getNeedsSync() || store.isMultiDevice(), System.currentTimeMillis() - startTime, content.getContent());
          } catch (InvalidUnidentifiedAccessHeaderException | UnregisteredUserException | MismatchedDevicesException | StaleDevicesException e) {
            // Non-technical failures shouldn't be retried with socket
            throw e;
          } catch (WebSocketUnavailableException e) {
            Log.i(TAG, "[sendMessage][" + timestamp + "] Unidentified pipe unavailable, falling back... (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
          } catch (IOException e) {
            Log.w(TAG, e);
            Log.w(TAG, "[sendMessage][" + timestamp + "] Unidentified pipe failed, falling back...");
          }
        }

        if (cancelationSignal != null && cancelationSignal.isCanceled()) {
          throw new CancelationException();
        }

        SendMessageResponse response = socket.sendMessage(messages, unidentifiedAccess);

        return SendMessageResult.success(recipient, messages.getDevices(), response.sentUnidentified(), response.getNeedsSync() || store.isMultiDevice(), System.currentTimeMillis() - startTime, content.getContent());

      } catch (InvalidKeyException ike) {
        Log.w(TAG, ike);
        unidentifiedAccess = Optional.absent();
      } catch (AuthorizationFailedException afe) {
        Log.w(TAG, afe);
        if (unidentifiedAccess.isPresent()) {
          unidentifiedAccess = Optional.absent();
        } else {
          throw afe;
        }
      } catch (MismatchedDevicesException mde) {
        Log.w(TAG, "[sendMessage][" + timestamp + "] Handling mismatched devices. (" + mde.getMessage() + ")");
        handleMismatchedDevices(socket, recipient, mde.getMismatchedDevices());
      } catch (StaleDevicesException ste) {
        Log.w(TAG, "[sendMessage][" + timestamp + "] Handling stale devices. (" + ste.getMessage() + ")");
        handleStaleDevices(recipient, ste.getStaleDevices());
      }
    }

    throw new IOException("Failed to resolve conflicts after " + RETRY_COUNT + " attempts!");
  }

  /**
   * Will send a message using sender keys to all of the specified recipients. It is assumed that
   * all of the recipients have UUIDs.
   *
   * This method will handle sending out SenderKeyDistributionMessages as necessary.
   */
  private List<SendMessageResult> sendGroupMessage(DistributionId             distributionId,
                                                   List<SignalServiceAddress> recipients,
                                                   List<UnidentifiedAccess>   unidentifiedAccess,
                                                   long                       timestamp,
                                                   Content                    content,
                                                   ContentHint                contentHint,
                                                   Optional<byte[]>           groupId,
                                                   boolean                    online,
                                                   SenderKeyGroupEvents       sendEvents)
      throws IOException, UntrustedIdentityException, NoSessionException, InvalidKeyException, InvalidRegistrationIdException
  {
    if (recipients.isEmpty()) {
      Log.w(TAG, "[sendGroupMessage][" + timestamp + "] Empty recipient list!");
      return Collections.emptyList();
    }

    Preconditions.checkArgument(recipients.size() == unidentifiedAccess.size(), "[" + timestamp + "] Unidentified access mismatch!");

    Map<ServiceId, UnidentifiedAccess> accessBySid     = new HashMap<>();
    Iterator<SignalServiceAddress>     addressIterator = recipients.iterator();
    Iterator<UnidentifiedAccess>       accessIterator  = unidentifiedAccess.iterator();

    while (addressIterator.hasNext()) {
      accessBySid.put(addressIterator.next().getServiceId(), accessIterator.next());
    }

    for (int i = 0; i < RETRY_COUNT; i++) {
      GroupTargetInfo            targetInfo     = buildGroupTargetInfo(recipients);
      Set<SignalProtocolAddress> sharedWith     = store.getSenderKeySharedWith(distributionId);
      List<SignalServiceAddress> needsSenderKey = targetInfo.destinations.stream()
                                                                         .filter(a -> !sharedWith.contains(a))
                                                                         .map(a -> ServiceId.parseOrThrow(a.getName()))
                                                                         .distinct()
                                                                         .map(SignalServiceAddress::new)
                                                                         .collect(Collectors.toList());
      if (needsSenderKey.size() > 0) {
        Log.i(TAG, "[sendGroupMessage][" + timestamp + "] Need to send the distribution message to " + needsSenderKey.size() + " addresses.");
        SenderKeyDistributionMessage           message = getOrCreateNewGroupSession(distributionId);
        List<Optional<UnidentifiedAccessPair>> access  = needsSenderKey.stream()
                                                                       .map(r -> {
                                                                         UnidentifiedAccess targetAccess = accessBySid.get(r.getServiceId());
                                                                         return Optional.of(new UnidentifiedAccessPair(targetAccess, targetAccess));
                                                                       })
                                                                       .collect(Collectors.toList());

        List<SendMessageResult> results = sendSenderKeyDistributionMessage(distributionId, needsSenderKey, access, message, groupId);

        List<SignalServiceAddress> successes = results.stream()
                                                      .filter(SendMessageResult::isSuccess)
                                                      .map(SendMessageResult::getAddress)
                                                      .collect(Collectors.toList());

        Set<String>                successSids      = successes.stream().map(a -> a.getServiceId().toString()).collect(Collectors.toSet());
        Set<SignalProtocolAddress> successAddresses = targetInfo.destinations.stream().filter(a -> successSids.contains(a.getName())).collect(Collectors.toSet());

        store.markSenderKeySharedWith(distributionId, successAddresses);

        Log.i(TAG, "[sendGroupMessage][" + timestamp + "] Successfully sent sender keys to " + successes.size() + "/" + needsSenderKey.size() + " recipients.");

        int failureCount = results.size() - successes.size();
        if (failureCount > 0) {
          Log.w(TAG, "[sendGroupMessage][" + timestamp + "] Failed to send sender keys to " + failureCount + " recipients. Sending back failed results now.");

          List<SendMessageResult> trueFailures = results.stream()
                                                        .filter(r -> !r.isSuccess())
                                                        .collect(Collectors.toList());

          Set<ServiceId> failedAddresses = trueFailures.stream()
                                                       .map(result -> result.getAddress().getServiceId())
                                                       .collect(Collectors.toSet());

          List<SendMessageResult> fakeNetworkFailures = recipients.stream()
                                                                  .filter(r -> !failedAddresses.contains(r.getServiceId()))
                                                                  .map(SendMessageResult::networkFailure)
                                                                  .collect(Collectors.toList());

          List<SendMessageResult> modifiedResults = new LinkedList<>();
          modifiedResults.addAll(trueFailures);
          modifiedResults.addAll(fakeNetworkFailures);

          return modifiedResults;
        } else {
          targetInfo = buildGroupTargetInfo(recipients);
        }
      }

      sendEvents.onSenderKeyShared();

      SignalServiceCipher cipher            = new SignalServiceCipher(localAddress, localDeviceId, store, sessionLock, null);
      SenderCertificate   senderCertificate = unidentifiedAccess.get(0).getUnidentifiedCertificate();

      byte[] ciphertext;
      try {
        ciphertext = cipher.encryptForGroup(distributionId, targetInfo.destinations, senderCertificate, content.toByteArray(), contentHint, groupId);
      } catch (org.whispersystems.libsignal.UntrustedIdentityException e) {
        throw new UntrustedIdentityException("Untrusted during group encrypt", e.getName(), e.getUntrustedIdentity());
      }

      sendEvents.onMessageEncrypted();

      byte[] joinedUnidentifiedAccess = new byte[16];
      for (UnidentifiedAccess access : unidentifiedAccess) {
        joinedUnidentifiedAccess = ByteArrayUtil.xor(joinedUnidentifiedAccess, access.getUnidentifiedAccessKey());
      }

      try {
        try {
          SendGroupMessageResponse response = new MessagingService.SendResponseProcessor<>(messagingService.sendToGroup(ciphertext, joinedUnidentifiedAccess, timestamp, online).blockingGet()).getResultOrThrow();
          return transformGroupResponseToMessageResults(targetInfo.devices, response, content);
        } catch (InvalidUnidentifiedAccessHeaderException | NotFoundException | GroupMismatchedDevicesException | GroupStaleDevicesException e) {
          // Non-technical failures shouldn't be retried with socket
          throw e;
        } catch (WebSocketUnavailableException e) {
          Log.i(TAG, "[sendGroupMessage][" + timestamp + "] Pipe unavailable, falling back... (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
        } catch (IOException e) {
          Log.w(TAG, "[sendGroupMessage][" + timestamp + "] Pipe failed, falling back... (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
        }

        SendGroupMessageResponse response = socket.sendGroupMessage(ciphertext, joinedUnidentifiedAccess, timestamp, online);
        return transformGroupResponseToMessageResults(targetInfo.devices, response, content);
      } catch (GroupMismatchedDevicesException e) {
        Log.w(TAG, "[sendGroupMessage][" + timestamp + "] Handling mismatched devices. (" + e.getMessage() + ")");
        for (GroupMismatchedDevices mismatched : e.getMismatchedDevices()) {
          SignalServiceAddress address = new SignalServiceAddress(ServiceId.parseOrThrow(mismatched.getUuid()), Optional.absent());
          handleMismatchedDevices(socket, address, mismatched.getDevices());
        }
      } catch (GroupStaleDevicesException e) {
        Log.w(TAG, "[sendGroupMessage][" + timestamp + "] Handling stale devices. (" + e.getMessage() + ")");
        for (GroupStaleDevices stale : e.getStaleDevices()) {
          SignalServiceAddress address = new SignalServiceAddress(ServiceId.parseOrThrow(stale.getUuid()), Optional.absent());
          handleStaleDevices(address, stale.getDevices());
        }
      }

      Log.w(TAG, "[sendGroupMessage][" + timestamp + "] Attempt failed (i = " + i + ")");
    }

    throw new IOException("Failed to resolve conflicts after " + RETRY_COUNT + " attempts!");
  }

  private GroupTargetInfo buildGroupTargetInfo(List<SignalServiceAddress> recipients) {
    List<String>                             addressNames         = recipients.stream().map(SignalServiceAddress::getIdentifier).collect(Collectors.toList());
    Set<SignalProtocolAddress>               destinations         = store.getAllAddressesWithActiveSessions(addressNames);
    Map<String, List<Integer>>               devicesByAddressName = new HashMap<>();

    destinations.addAll(recipients.stream()
                                  .map(a -> new SignalProtocolAddress(a.getIdentifier(), SignalServiceAddress.DEFAULT_DEVICE_ID))
                                  .collect(Collectors.toList()));

    for (SignalProtocolAddress destination : destinations) {
      List<Integer> devices = devicesByAddressName.containsKey(destination.getName()) ? devicesByAddressName.get(destination.getName()) : new LinkedList<>();
      devices.add(destination.getDeviceId());
      devicesByAddressName.put(destination.getName(), devices);
    }

    Map<SignalServiceAddress, List<Integer>> recipientDevices = new HashMap<>();

    for (SignalServiceAddress recipient : recipients) {
      if (devicesByAddressName.containsKey(recipient.getIdentifier())) {
        recipientDevices.put(recipient, devicesByAddressName.get(recipient.getIdentifier()));
      }
    }

    return new GroupTargetInfo(new ArrayList<>(destinations), recipientDevices);
  }


  private static final class GroupTargetInfo {
    private final List<SignalProtocolAddress>              destinations;
    private final Map<SignalServiceAddress, List<Integer>> devices;

    private GroupTargetInfo(List<SignalProtocolAddress> destinations, Map<SignalServiceAddress, List<Integer>> devices) {
      this.destinations = destinations;
      this.devices      = devices;
    }
  }

  private List<SendMessageResult> transformGroupResponseToMessageResults(Map<SignalServiceAddress, List<Integer>> recipients, SendGroupMessageResponse response, Content content) {
    Set<ServiceId> unregistered = response.getUnsentTargets();

    List<SendMessageResult> failures = unregistered.stream()
                                                   .map(SignalServiceAddress::new)
                                                   .map(SendMessageResult::unregisteredFailure)
                                                   .collect(Collectors.toList());

    List<SendMessageResult> success = recipients.keySet()
                                                .stream()
                                                .filter(r -> !unregistered.contains(r.getServiceId()))
                                                .map(a -> SendMessageResult.success(a, recipients.get(a), true, store.isMultiDevice(), -1, Optional.of(content)))
                                                .collect(Collectors.toList());

    List<SendMessageResult> results = new ArrayList<>(success.size() + failures.size());
    results.addAll(success);
    results.addAll(failures);

    return results;
  }

  private List<AttachmentPointer> createAttachmentPointers(Optional<List<SignalServiceAttachment>> attachments) throws IOException {
    List<AttachmentPointer> pointers = new LinkedList<>();

    if (!attachments.isPresent() || attachments.get().isEmpty()) {
      return pointers;
    }

    for (SignalServiceAttachment attachment : attachments.get()) {
      if (attachment.isStream()) {
        Log.i(TAG, "Found attachment, creating pointer...");
        pointers.add(createAttachmentPointer(attachment.asStream()));
      } else if (attachment.isPointer()) {
        Log.i(TAG, "Including existing attachment pointer...");
        pointers.add(createAttachmentPointer(attachment.asPointer()));
      }
    }

    return pointers;
  }

  private AttachmentPointer createAttachmentPointer(SignalServiceAttachmentPointer attachment) {
    return AttachmentPointerUtil.createAttachmentPointer(attachment);
  }

  private AttachmentPointer createAttachmentPointer(SignalServiceAttachmentStream attachment)
      throws IOException
  {
    return createAttachmentPointer(uploadAttachment(attachment));
  }

  private TextAttachment createTextAttachment(SignalServiceTextAttachment attachment) throws IOException {
    TextAttachment.Builder builder = TextAttachment.newBuilder();

    if (attachment.getStyle().isPresent()) {
      switch (attachment.getStyle().get()) {
        case DEFAULT:
          builder.setTextStyle(TextAttachment.Style.DEFAULT);
          break;
        case REGULAR:
          builder.setTextStyle(TextAttachment.Style.REGULAR);
          break;
        case BOLD:
          builder.setTextStyle(TextAttachment.Style.BOLD);
          break;
        case SERIF:
          builder.setTextStyle(TextAttachment.Style.SERIF);
          break;
        case SCRIPT:
          builder.setTextStyle(TextAttachment.Style.SCRIPT);
          break;
        case CONDENSED:
          builder.setTextStyle(TextAttachment.Style.CONDENSED);
          break;
        default:
          throw new AssertionError("Unknown type: " + attachment.getStyle().get());
      }
    }

    TextAttachment.Gradient.Builder gradientBuilder = TextAttachment.Gradient.newBuilder();

    if (attachment.getBackgroundGradient().isPresent()) {
      SignalServiceTextAttachment.Gradient gradient = attachment.getBackgroundGradient().get();

      if (gradient.getStartColor().isPresent()) gradientBuilder.setStartColor(gradient.getStartColor().get());
      if (gradient.getEndColor().isPresent())   gradientBuilder.setEndColor(gradient.getEndColor().get());
      if (gradient.getAngle().isPresent())      gradientBuilder.setAngle(gradient.getAngle().get());

      builder.setGradient(gradientBuilder.build());
    }

    if (attachment.getText().isPresent())                builder.setText(attachment.getText().get());
    if (attachment.getTextForegroundColor().isPresent()) builder.setTextForegroundColor(attachment.getTextForegroundColor().get());
    if (attachment.getTextBackgroundColor().isPresent()) builder.setTextBackgroundColor(attachment.getTextBackgroundColor().get());
    if (attachment.getPreview().isPresent())             builder.setPreview(createPreview(attachment.getPreview().get()));
    if (attachment.getBackgroundColor().isPresent())     builder.setColor(attachment.getBackgroundColor().get());

    return builder.build();
  }

  private OutgoingPushMessageList getEncryptedMessages(PushServiceSocket            socket,
                                                       SignalServiceAddress         recipient,
                                                       Optional<UnidentifiedAccess> unidentifiedAccess,
                                                       long                         timestamp,
                                                       EnvelopeContent              plaintext,
                                                       boolean                      online)
      throws IOException, InvalidKeyException, UntrustedIdentityException
  {
    List<OutgoingPushMessage> messages = new LinkedList<>();

    List<Integer> subDevices = store.getSubDeviceSessions(recipient.getIdentifier());

    List<Integer> deviceIds = new ArrayList<>(subDevices.size() + 1);
    deviceIds.add(SignalServiceAddress.DEFAULT_DEVICE_ID);
    deviceIds.addAll(subDevices);

    if (recipient.matches(localAddress)) {
      deviceIds.remove(Integer.valueOf(localDeviceId));
    }

    for (int deviceId : deviceIds) {
      if (deviceId == SignalServiceAddress.DEFAULT_DEVICE_ID || store.containsSession(new SignalProtocolAddress(recipient.getIdentifier(), deviceId))) {
        messages.add(getEncryptedMessage(socket, recipient, unidentifiedAccess, deviceId, plaintext));
      }
    }

    return new OutgoingPushMessageList(recipient.getIdentifier(), timestamp, messages, online);
  }

  private OutgoingPushMessage getEncryptedMessage(PushServiceSocket            socket,
                                                  SignalServiceAddress         recipient,
                                                  Optional<UnidentifiedAccess> unidentifiedAccess,
                                                  int                          deviceId,
                                                  EnvelopeContent              plaintext)
      throws IOException, InvalidKeyException, UntrustedIdentityException
  {
    SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipient.getIdentifier(), deviceId);
    SignalServiceCipher   cipher                = new SignalServiceCipher(localAddress, localDeviceId, store, sessionLock, null);

    if (!store.containsSession(signalProtocolAddress)) {
      try {
        List<PreKeyBundle> preKeys = socket.getPreKeys(recipient, unidentifiedAccess, deviceId);

        for (PreKeyBundle preKey : preKeys) {
          try {
            SignalProtocolAddress preKeyAddress  = new SignalProtocolAddress(recipient.getIdentifier(), preKey.getDeviceId());
            SignalSessionBuilder  sessionBuilder = new SignalSessionBuilder(sessionLock, new SessionBuilder(store, preKeyAddress));
            sessionBuilder.process(preKey);
          } catch (org.whispersystems.libsignal.UntrustedIdentityException e) {
            throw new UntrustedIdentityException("Untrusted identity key!", recipient.getIdentifier(), preKey.getIdentityKey());
          }
        }

        if (eventListener.isPresent()) {
          eventListener.get().onSecurityEvent(recipient);
        }
      } catch (InvalidKeyException e) {
        throw new IOException(e);
      }
    }

    try {
      return cipher.encrypt(signalProtocolAddress, unidentifiedAccess, plaintext);
    } catch (org.whispersystems.libsignal.UntrustedIdentityException e) {
      throw new UntrustedIdentityException("Untrusted on send", recipient.getIdentifier(), e.getUntrustedIdentity());
    }
  }

  private void handleMismatchedDevices(PushServiceSocket socket, SignalServiceAddress recipient,
                                       MismatchedDevices mismatchedDevices)
      throws IOException, UntrustedIdentityException
  {
    try {
      Log.w(TAG, "[handleMismatchedDevices] Address: " + recipient.getIdentifier() + ", ExtraDevices: " + mismatchedDevices.getExtraDevices() + ", MissingDevices: " + mismatchedDevices.getMissingDevices());
      archiveSessions(recipient, mismatchedDevices.getExtraDevices());

      for (int missingDeviceId : mismatchedDevices.getMissingDevices()) {
        PreKeyBundle preKey = socket.getPreKey(recipient, missingDeviceId);

        try {
          SignalSessionBuilder sessionBuilder = new SignalSessionBuilder(sessionLock, new SessionBuilder(store, new SignalProtocolAddress(recipient.getIdentifier(), missingDeviceId)));
          sessionBuilder.process(preKey);
        } catch (org.whispersystems.libsignal.UntrustedIdentityException e) {
          throw new UntrustedIdentityException("Untrusted identity key!", recipient.getIdentifier(), preKey.getIdentityKey());
        }
      }
    } catch (InvalidKeyException e) {
      throw new IOException(e);
    }
  }

  private void handleStaleDevices(SignalServiceAddress recipient, StaleDevices staleDevices) {
    Log.w(TAG, "[handleStaleDevices] Address: " + recipient.getIdentifier() + ", StaleDevices: " + staleDevices.getStaleDevices());
    archiveSessions(recipient, staleDevices.getStaleDevices());
  }

  private void archiveSessions(SignalServiceAddress recipient, List<Integer> devices) {
    List<SignalProtocolAddress> addressesToClear = convertToProtocolAddresses(recipient, devices);

    for (SignalProtocolAddress address : addressesToClear) {
      store.archiveSession(address);
    }
  }

  private List<SignalProtocolAddress> convertToProtocolAddresses(SignalServiceAddress recipient, List<Integer> devices) {
    List<SignalProtocolAddress> addresses = new ArrayList<>(devices.size());

    for (int staleDeviceId : devices) {
      addresses.add(new SignalProtocolAddress(recipient.getServiceId().toString(), staleDeviceId));

      if (recipient.getNumber().isPresent()) {
        addresses.add(new SignalProtocolAddress(recipient.getNumber().get(), staleDeviceId));
      }
    }

    return addresses;
  }

  private Optional<UnidentifiedAccess> getTargetUnidentifiedAccess(Optional<UnidentifiedAccessPair> unidentifiedAccess) {
    if (unidentifiedAccess.isPresent()) {
      return unidentifiedAccess.get().getTargetUnidentifiedAccess();
    }

    return Optional.absent();
  }

  private List<Optional<UnidentifiedAccess>> getTargetUnidentifiedAccess(List<Optional<UnidentifiedAccessPair>> unidentifiedAccess) {
    List<Optional<UnidentifiedAccess>> results = new LinkedList<>();

    for (Optional<UnidentifiedAccessPair> item : unidentifiedAccess) {
      if (item.isPresent()) results.add(item.get().getTargetUnidentifiedAccess());
      else                  results.add(Optional.<UnidentifiedAccess>absent());
    }

    return results;
  }

  private EnvelopeContent enforceMaxContentSize(EnvelopeContent content) {
    int size = content.size();

    if (maxEnvelopeSize > 0 && size > maxEnvelopeSize) {
      throw new ContentTooLargeException(size);
    }
    return content;
  }

  private Content enforceMaxContentSize(Content content) {
    int size = content.toByteArray().length;

    if (maxEnvelopeSize > 0 && size > maxEnvelopeSize) {
      throw new ContentTooLargeException(size);
    }
    return content;
  }

  public interface EventListener {
    void onSecurityEvent(SignalServiceAddress address);
  }

  public interface IndividualSendEvents {
    IndividualSendEvents EMPTY = new IndividualSendEvents() {
      @Override
      public void onMessageEncrypted() { }

      @Override
      public void onMessageSent() { }

      @Override
      public void onSyncMessageSent() { }
    };

    void onMessageEncrypted();
    void onMessageSent();
    void onSyncMessageSent();
  }

  public interface SenderKeyGroupEvents {
    SenderKeyGroupEvents EMPTY = new SenderKeyGroupEvents() {
      @Override
      public void onSenderKeyShared() { }

      @Override
      public void onMessageEncrypted() { }

      @Override
      public void onMessageSent() { }

      @Override
      public void onSyncMessageSent() { }
    };

    void onSenderKeyShared();
    void onMessageEncrypted();
    void onMessageSent();
    void onSyncMessageSent();
  }

  public interface LegacyGroupEvents {
    LegacyGroupEvents EMPTY = new LegacyGroupEvents() {
      @Override
      public void onMessageSent() { }

      @Override
      public void onSyncMessageSent() { }
    };

    void onMessageSent();
    void onSyncMessageSent();
  }
}
