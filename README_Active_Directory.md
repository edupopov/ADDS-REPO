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

## Estrutura sugerida do repositório

```text
/
├── README.md
├── scripts/
│   ├── checks/
│   ├── users/
│   ├── groups/
│   ├── computers/
│   ├── ous/
│   ├── gpo/
│   ├── replication/
│   ├── security/
│   └── reports/
├── docs/
│   ├── procedures/
│   ├── standards/
│   ├── troubleshooting/
│   └── architecture/
├── templates/
│   ├── ou-structure/
│   ├── group-naming/
│   └── access-review/
├── training/
│   ├── microsoft-learn/
│   ├── internal-materials/
│   └── labs/
└── references/
    ├── official-docs.md
    ├── useful-links.md
    └── recommended-reading.md
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

### Scripts

```text
Get-ADInactiveUsers.ps1
Get-ADDisabledComputers.ps1
New-ADOUStructure.ps1
Export-ADPrivilegedGroups.ps1
Test-ADReplicationHealth.ps1
```

### Documentos

```text
procedure-ad-user-cleanup.md
standard-ou-structure.md
troubleshooting-ad-replication.md
security-review-privileged-groups.md
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

## Links oficiais e treinamentos recomendados

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

---

## Política de uso

Os scripts e documentos deste repositório devem ser utilizados com responsabilidade técnica. Qualquer execução em ambiente produtivo deve observar os processos internos de mudança, governança, segurança e aprovação.

Este repositório não substitui a análise técnica do ambiente nem dispensa validações prévias antes da execução de comandos administrativos.

---

## Manutenção do repositório

Recomenda-se revisar periodicamente:

- Scripts obsoletos.
- Links quebrados.
- Documentação desatualizada.
- Procedimentos que não refletem mais o ambiente atual.
- Permissões de acesso ao repositório.
- Evidências e exemplos antigos.

---

## Referências

- Microsoft Learn: [Active Directory Domain Services - Training](https://learn.microsoft.com/pt-br/training/paths/active-directory-domain-services/)
- Microsoft Learn: [Administer Active Directory Domain Services](https://learn.microsoft.com/en-us/training/paths/administer-active-directory-domain-services/)
- Microsoft Learn: [Windows Server documentation](https://learn.microsoft.com/windows-server/)
- Microsoft Learn: [Group Policy overview](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview)

---

## Licença e responsabilidade

Defina neste espaço a licença de uso do repositório, quando aplicável.

Os responsáveis pelo repositório devem garantir que scripts com impacto operacional sejam revisados, testados e documentados antes da utilização em produção.
