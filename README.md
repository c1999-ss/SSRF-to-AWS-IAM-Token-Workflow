# SSRF-to-AWS-IAM-Token-Workflow

## ⚠️ YASAL UYARI (LEGAL DISCLAIMER)

**LUR Toolkit**, yalnızca **yetkili güvenlik testleri**, **CTF yarışmaları**, **araştırma ve eğitim amaçlı** kullanılması için geliştirilmiştir.

Bu aracı kullanarak gerçekleştirilen tüm işlemlerden **tamamen kullanıcı sorumludur**.

Yapılan herhangi bir izinsiz kullanım, veri sızdırma, sisteme izinsiz erişim, veri silme veya değiştirme gibi faaliyetlerin;
- ulusal ve uluslararası yasalar kapsamında **suç teşkil edebileceği**,
- ağır hukuki ve cezai yaptırımlarla sonuçlanabileceği unutulmamalıdır.

Bu araç, **kötüye kullanım amacıyla** kullanılmamalıdır.
Aracın geliştiricisi, katkı sağlayanlar veya barındırıldığı platform (örn. GitHub), **kullanıcıların yapacağı hiçbir eylemden sorumlu değildir.**

> **Kısaca:**
> Bu aracı ne amaçla kullanırsan kullan, tüm sorumluluk **sana** aittir.
> Yaptığın her şeyin **yasal zemini olduğundan emin ol.**

**👮 Etik kal, yasal kal, kırıcı değil geliştirici ol.**



Bu Tool Nedir?

SSRF-to-AWS-IAM-Token-Workflow, bir web uygulamasında bulunan SSRF (Server-Side Request Forgery - Sunucu Tarafı İstek Sahteciliği) zafiyetini kullanarak, o uygulamanın çalıştığı AWS EC2 sunucusunun geçici IAM kimlik bilgilerini (credentials/token) çalmayı otomatize eden bir araçtır.

Kısacası, bir güvenlik uzmanının veya sızma testi yapan kişinin, bulduğu bir SSRF zafiyetinin ne kadar tehlikeli olabileceğini kanıtlamasına yardımcı olur.

Ne İşe Yarar ve Nasıl Çalışır?

Bu aracın ne işe yaradığını anlamak için önce temel kavramları bilmek gerekir:

SSRF (Sunucu Tarafı İstek Sahteciliği): Bu bir web uygulaması zafiyetidir. Saldırgan, zafiyetli sunucunun kendisi adına başka bir sunucuya (iç veya dış ağda) istek göndermesini sağlar. Normalde bir web sitesine siz kendi tarayıcınızdan istek yaparsınız, SSRF'de ise web sitesinin sunucusuna "git şu adrese benim için bir istek yap" demiş olursunuz.

AWS EC2 Metadata Service: AWS'de çalışan her sanal sunucunun (EC2 instance), kendisi hakkında bilgi alabileceği özel bir IP adresi vardır: 169.254.169.254. Bu IP adresi, sadece o EC2 sunucusunun içinden erişilebilen bir servistir. Bu servisten sunucunun adını, ID'sini, güvenlik gruplarını ve en önemlisi, o sunucuya atanmış IAM Rolü'nün geçici güvenlik kimlik bilgilerini (AccessKeyId, SecretAccessKey, SessionToken) alabilirsiniz. Bu kimlik bilgileri, sunucunun diğer AWS servisleriyle (S3, veritabanları vb.) etkileşime girmesi için kullanılır.

Aracın Çalışma Mantığı (Adım Adım):

Bu araç, yukarıdaki iki konsepti birleştirir:

Tespit: Bir güvenlik araştırmacısı, https://example.com/load_image?url=http://externalsite.com/image.jpg gibi bir adreste SSRF zafiyeti bulur. Yani url parametresine yazdığı adrese sunucunun istek gönderdiğini fark eder.

Hedef Belirleme: Araştırmacı, bu sunucunun bir AWS EC2 üzerinde çalıştığından şüphelenir. Amacı, sunucunun kendi içindeki Metadata servisine (169.254.169.254) ulaşmaktır.

Aracın Kullanımı: Araştırmacı, bu aracı çalıştırır ve zafiyetli URL'yi araca verir. Araç şu işlemleri otomatik olarak yapar:

Adım 1: IAM Rolünü Bulma: Araç, zafiyetli URL'yi kullanarak sunucunun http://169.254.169.254/latest/meta-data/iam/security-credentials/ adresine bir istek göndermesini sağlar. Bu isteğin cevabında, EC2'ye atanmış olan IAM rolünün adı döner (örneğin, my-ec2-s3-role).

Adım 2: Kimlik Bilgilerini Çekme: Araç, ilk adımda öğrendiği rol adını kullanarak yeni bir URL oluşturur: http://169.254.169.254/latest/meta-data/iam/security-credentials/my-ec2-s3-role. Tekrar SSRF zafiyetini kullanarak sunucunun bu yeni adrese istek yapmasını sağlar.

Adım 3: Sonuçları Gösterme: Bu ikinci isteğin cevabı, JSON formatında geçici kimlik bilgilerini içerir:

code
JSON
download
content_copy
expand_less
{
  "Code" : "Success",
  "LastUpdated" : "2023-11-20T10:00:00Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA...",
  "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token" : "IQoJb3JpZ2luX2Vj...",
  "Expiration" : "2023-11-20T16:15:00Z"
}

Araç bu bilgileri ayrıştırır (parse eder) ve kullanıcıya temiz bir şekilde sunar.

Kimler Kullanır?

Sızma Testi Uzmanları (Penetration Testers): Bir müşterinin sistemini test ederken buldukları bir SSRF zafiyetinin ne kadar kritik olduğunu göstermek için kullanırlar. "Sadece başka sitelere istek attırabiliyorum" demek yerine, "Sunucunuzun tüm AWS yetkilerini ele geçirdim" demek çok daha etkilidir.

Bug Bounty Avcıları: Buldukları zafiyetin etkisini (impact) artırarak daha yüksek ödül almak için kullanırlar.

Güvenlik Araştırmacıları: Bu tür saldırı vektörlerini anlamak ve savunma mekanizmaları geliştirmek için eğitim ve araştırma amaçlı kullanırlar.

Bu Saldırıdan Nasıl Korunulur?

Bu tür bir saldırıyı önlemek için birkaç yöntem vardır:

SSRF Zafiyetini Gidermek: En temel yöntem budur. Kullanıcıdan alınan URL'leri doğrudan kullanmak yerine, sadece izin verilen (whitelist) alan adlarına veya IP'lere istek yapılmasına izin verilmelidir.

IMDSv2 (Instance Metadata Service Version 2) Kullanmak: AWS, bu saldırıyı önlemek için Metadata Servisi'nin ikinci versiyonunu (IMDSv2) çıkardı. IMDSv2, kimlik bilgilerini almadan önce ek bir PUT isteği ile bir "session token" alınmasını zorunlu kılar. Basit bir SSRF zafiyeti GET isteği yaptığı için bu korumayı atlayamaz. Bu, en etkili savunma yöntemidir.

En Az Yetki Prensibi (Principle of Least Privilege): EC2 sunucusuna atanan IAM rolünün yetkileri, sadece işini yapması için gereken minimum seviyede olmalıdır. Böylece kimlik bilgileri çalınsa bile saldırganın yapabileceği şeyler sınırlı olur.

WAF (Web Application Firewall): 169.254.169.254 gibi IP adreslerine yapılan istekleri tespit edip engelleyecek kurallar yazılabilir.

Özetle, bu araç, bir SSRF zafiyetinin AWS ortamındaki potansiyel etkisini göstermek ve bu süreci otomatize etmek için kullanılan, güvenlik uzmanları için geliştirilmiş bir araçtır. Kötü niyetli bir saldırı aracı olmaktan ziyade, bir zafiyetin ciddiyetini kanıtlamaya ve raporlamaya yarar.
