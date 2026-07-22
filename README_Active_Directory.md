# Repositório de Active Directory

Este repositório centraliza scripts, procedimentos, consultas, referências técnicas e materiais de apoio relacionados à administração, verificação, organização e governança de ambientes **Active Directory Domain Services (AD DS)**.

O objetivo é manter uma base organizada, reutilizável e tecnicamente confiável para apoiar atividades de operação, auditoria, troubleshooting, padronização de estruturas e capacitação técnica.
---
## Objetivos do repositório

- Disponibilizar scripts para checagem e validação do ambiente Active Directory.
- Apoiar a criação e padronização de estruturas como OUs, grupos, contas administrativas e objetos de diretório.
- Centralizar links de documentação oficial, artigos técnicos e treinamentos relacionados a AD DS.
- Facilitar atividades de auditoria, segurança, governança de identidade e revisão operacional.
- Servir como base de conhecimento para times de infraestrutura, segurança, suporte e administração de identidade.
---

## Escopo

Este repositório contempla conteúdos relacionados a:

- Active Directory Domain Services.
- Controladores de domínio.
- Unidades Organizacionais (OUs).
- Usuários, grupos e computadores.
- Políticas de Grupo (GPOs).
- Replicação, sites e serviços.
- Funções FSMO.
- DNS integrado ao Active Directory.
- Segurança, hardening e governança de identidade.
- Administração via PowerShell.
- Inventário, auditoria e limpeza de objetos obsoletos.

---
## Training and Certifications

## Microsoft Training

## Active Directory Domain Services / Windows Server (ADDS)
1. https://learn.microsoft.com/en-us/training/paths/active-directory-domain-services/
2. https://learn.microsoft.com/en-us/training/paths/administer-active-directory-domain-services/
3. https://learn.microsoft.com/en-us/training/paths/deploy-manage-identity-infrastructure/
4. https://learn.microsoft.com/en-us/credentials/applied-skills/administer-active-directory-domain-services/

## Entra ID
1. https://learn.microsoft.com/en-us/training/entra/
2. https://learn.microsoft.com/en-us/training/paths/manage-identity-and-access/
3. https://learn.microsoft.com/en-us/training/paths/describe-capabilities-of-microsoft-identity-access/
4. https://learn.microsoft.com/en-us/training/modules/explore-identity-azure-active-directory/
5. https://learn.microsoft.com/en-us/training/paths/az-400-develop-security-compliance-plan/
6. Active Directory Certificate Services (ADCS)
7. https://learn.microsoft.com/en-us/training/modules/implement-manage-active-directory-certificate-services/
8. Microsoft Certifications

## Microsoft Certified: Windows Server Hybrid Administrator
NOTE: THESE ARE BEING RETIRED IN SEPTEMBER 2026! New AZ-802 is replacing them!

1. https://learn.microsoft.com/en-us/credentials/certifications/windows-server-hybrid-administrator/
2. https://learn.microsoft.com/en-us/credentials/certifications/exams/az-800/
3. https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/az-800
4. https://learn.microsoft.com/en-us/credentials/certifications/exams/az-801/
5. https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/az-801
6. Microsoft Certified: Identity and Access Administrator Associate
7. https://learn.microsoft.com/en-us/credentials/certifications/identity-and-access-administrator/?practice-assessment-type=certification
8. https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-300

## Microsoft Certified: Azure Security Engineer Associate [AZ-500]:
* NOTE: THIS IS BEING RETIRED IN 2026! New SC-500 is replacing it.
https://learn.microsoft.com/en-us/credentials/certifications/azure-security-engineer/?practice-assessment-type=certification
Applied Skills (Mini certifications)
Administer Active Directory Domain Services: https://learn.microsoft.com/en-us/credentials/applied-skills/administer-active-directory-domain-services/
```
---

## Categorias de scripts

### 1. Checagens do ambiente

Scripts utilizados para validar o estado geral do Active Directory, incluindo:

- Saúde dos controladores de domínio.
- Replicação entre DCs.
- Estado das funções FSMO.
- Validação de DNS.
- Objetos desabilitados ou obsoletos.
- Contas sem uso recente.
- Grupos com permissões críticas.
- Políticas aplicadas ao domínio.

### 2. Criação e padronização de estruturas

Scripts utilizados para criar ou ajustar estruturas administrativas, como:

- Unidades Organizacionais.
- Grupos de segurança.
- Grupos de distribuição.
- Contas de serviço.
- Estruturas administrativas por área, localidade ou função.
- Delegações de permissões.

### 3. Relatórios e auditoria

Scripts voltados para extração de informações e geração de relatórios, incluindo:

- Usuários ativos e inativos.
- Contas recentemente criadas ou modificadas.
- Computadores sem logon recente.
- Grupos privilegiados.
- Membros de grupos administrativos.
- Alterações relevantes em objetos do diretório.
- Exportações em CSV para análise ou evidência.

### 4. Segurança e governança

Scripts e documentos relacionados a controles de segurança, tais como:

- Identificação de contas privilegiadas.
- Revisão de membros de grupos administrativos.
- Contas com senha que nunca expira.
- Contas de serviço sem documentação.
- Usuários desabilitados mantidos no diretório.
- Objetos sem proprietário definido.
- Recomendações para redução da superfície de ataque.

---

## Requisitos recomendados

Antes de executar qualquer script, valide os seguintes pontos:

- Executar em ambiente homologado sempre que possível.
- Revisar o código antes da execução.
- Utilizar conta com privilégio mínimo necessário.
- Registrar evidências antes e depois da execução.
- Evitar alterações diretas em produção sem aprovação formal.
- Documentar parâmetros, escopo e impacto esperado.
- Testar comandos destrutivos com opções como `-WhatIf`, quando aplicável.

---

## Boas práticas para scripts PowerShell

Todos os scripts devem seguir, sempre que possível, as seguintes recomendações:

- Incluir cabeçalho com objetivo, autor, data e histórico de alterações.
- Utilizar parâmetros documentados.
- Validar entradas antes da execução.
- Tratar erros com `try`, `catch` e `finally`, quando aplicável.
- Gerar logs de execução.
- Não armazenar credenciais em texto claro.
- Evitar caminhos fixos sem necessidade.
- Usar comentários claros apenas quando agregarem contexto técnico.
- Exportar resultados em formato padronizado, como CSV ou JSON.

Exemplo de cabeçalho sugerido:

```powershell
<#
.SYNOPSIS
    Descrição resumida do script.

.DESCRIPTION
    Explicação detalhada sobre a finalidade, escopo e comportamento esperado.

.AUTHOR
    Nome do responsável pelo script.

.VERSION
    1.0.0

.LASTUPDATED
    AAAA-MM-DD

.NOTES
    Informar pré-requisitos, permissões necessárias e eventuais riscos operacionais.
#>
```
---

## Convenção sugerida de nomes

Para manter o repositório organizado, recomenda-se utilizar nomes objetivos e padronizados.

```
---

## Fluxo recomendado de contribuição

1. Criar uma branch específica para a alteração.
2. Incluir ou modificar o script/documento necessário.
3. Validar a execução em ambiente controlado.
4. Atualizar a documentação correspondente.
5. Registrar exemplos de uso quando aplicável.
6. Submeter pull request para revisão técnica.
7. Aguardar aprovação antes de realizar merge na branch principal.

---

## Padrão mínimo para documentação de scripts

Cada script deve conter, no mínimo:

- Finalidade.
- Pré-requisitos.
- Permissões necessárias.
- Parâmetros disponíveis.
- Exemplos de execução.
- Tipo de saída gerada.
- Riscos ou impactos operacionais.
- Procedimento de rollback, quando aplicável.

Modelo sugerido:

```markdown
# Nome do script

## Objetivo
Descrever a finalidade do script.

## Pré-requisitos
Listar módulos, permissões e dependências.

## Como executar
```powershell
./NomeDoScript.ps1 -Parametro Valor
```

## Saída esperada
Descrever arquivos, logs ou informações apresentadas.

## Observações
Incluir riscos, limitações e recomendações.
```

---

## Atenção a scripts destrutivos

Scripts que realizam exclusão, movimentação, alteração em massa, desabilitação de contas ou mudanças em permissões devem ser tratados como críticos.

Recomendações obrigatórias:

- Exigir revisão por outro profissional técnico.
- Possuir modo de simulação, preferencialmente com `-WhatIf`.
- Gerar relatório prévio dos objetos impactados.
- Registrar log detalhado da execução.
- Possuir plano de reversão documentado.
- Ser executado apenas após aprovação formal.

---

### Microsoft Learn

- [Active Directory Domain Services - Training](https://learn.microsoft.com/pt-br/training/paths/active-directory-domain-services/)
- [Administer Active Directory Domain Services](https://learn.microsoft.com/en-us/training/paths/administer-active-directory-domain-services/)
- [Documentação do Windows Server](https://learn.microsoft.com/windows-server/)
- [Documentação de Group Policy](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview)
- [Active Directory Domain Services Overview](https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

### Temas recomendados para estudo

- Fundamentos de AD DS.
- Florestas, domínios, sites e OUs.
- Administração de controladores de domínio.
- Funções FSMO.
- Group Policy Objects.
- Replicação e troubleshooting.
- Delegação administrativa.
- Segurança de contas privilegiadas.
- Monitoramento e manutenção do diretório.
- Integração com ambientes híbridos.

