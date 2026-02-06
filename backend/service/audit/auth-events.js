
import { auditLog } from './audit-log.js';

const CATEGORY = 'AUTH';

/**
 * Logs de diagnóstico para segurança e autenticação.
 */
export const authEvents = {
    // SUCESSO
    loginSuccess: (userId, ip, userAgent) => 
        auditLog.info(CATEGORY, 'Login bem-sucedido.', { userId, ip, userAgent }),
    
    googleAuthSuccess: (userId, email, isNewUser, ip, userAgent) => 
        auditLog.info(CATEGORY, `Autenticação com Google ${isNewUser ? '(novo usuário)' : 'bem-sucedida'}.`, { userId, email, isNewUser, ip, userAgent }),

    passwordChangeSuccess: (userId, ip) => 
        auditLog.info(CATEGORY, 'Senha alterada com sucesso.', { userId, ip }),

    passwordResetRequested: (email, ip) => 
        auditLog.info(CATEGORY, 'Solicitação de redefinição de senha.', { email, ip }),

    passwordResetCompleted: (userId, ip) => 
        auditLog.info(CATEGORY, 'Senha redefinida com sucesso.', { userId, ip }),

    // FALHAS E ERROS
    loginFailure: (email, ip, userAgent, reason) => 
        auditLog.warn(CATEGORY, `Falha no login para ${email}: ${reason}`, { email, ip, userAgent }),

    userNotFound: (email, ip, userAgent) => 
        auditLog.warn(CATEGORY, 'Tentativa de login com e-mail não cadastrado.', { email, ip, userAgent }),

    passwordMismatch: (email, ip, userAgent) => 
        auditLog.warn(CATEGORY, 'Tentativa de login com senha incorreta.', { email, ip, userAgent }),

    registrationFailed: (email, ip, reason) => 
        auditLog.warn(CATEGORY, `Falha no registro para ${email}: ${reason}`, { email, ip, reason }),

    tokenValidationFailed: (token, ip, userAgent, reason) => 
        auditLog.warn(CATEGORY, `Validação de token falhou: ${reason}`, { reason, tokenUsed: token, ip, userAgent }),

    googleTokenInvalid: (ip, userAgent, reason) => 
        auditLog.warn(CATEGORY, 'Token de autenticação do Google inválido ou expirado.', { ip, userAgent, reason }),

    passwordChangeFailure: (userId, ip, reason) => 
        auditLog.warn(CATEGORY, `Tentativa de alteração de senha falhou: ${reason}`, { userId, ip }),

    sessionRevoked: (revokedBy, targetUserId, sessionId) => 
        auditLog.warn(CATEGORY, 'Sessão de usuário revogada.', { revokedBy, targetUserId, sessionId }),
        
    // ERROS CRÍTICOS
    authDbError: (operation, email, ip, userAgent, error) => 
        auditLog.error(CATEGORY, `Erro de banco de dados durante a autenticação (${operation}).`, { email, ip, userAgent, error }),
};
