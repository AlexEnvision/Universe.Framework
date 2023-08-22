﻿//  ╔═════════════════════════════════════════════════════════════════════════════════╗
//  ║                                                                                 ║
//  ║   Copyright 2021 Universe.Framework                                             ║
//  ║                                                                                 ║
//  ║   Licensed under the Apache License, Version 2.0 (the "License");               ║
//  ║   you may not use this file except in compliance with the License.              ║
//  ║   You may obtain a copy of the License at                                       ║
//  ║                                                                                 ║
//  ║       http://www.apache.org/licenses/LICENSE-2.0                                ║
//  ║                                                                                 ║
//  ║   Unless required by applicable law or agreed to in writing, software           ║
//  ║   distributed under the License is distributed on an "AS IS" BASIS,             ║
//  ║   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.      ║
//  ║   See the License for the specific language governing permissions and           ║
//  ║   limitations under the License.                                                ║
//  ║                                                                                 ║
//  ║                                                                                 ║
//  ║   Copyright 2021 Universe.Framework                                             ║
//  ║                                                                                 ║
//  ║   Лицензировано согласно Лицензии Apache, Версия 2.0 ("Лицензия");              ║
//  ║   вы можете использовать этот файл только в соответствии с Лицензией.           ║
//  ║   Вы можете найти копию Лицензии по адресу                                      ║
//  ║                                                                                 ║
//  ║       http://www.apache.org/licenses/LICENSE-2.0.                               ║
//  ║                                                                                 ║
//  ║   За исключением случаев, когда это регламентировано существующим               ║
//  ║   законодательством или если это не оговорено в письменном соглашении,          ║
//  ║   программное обеспечение распространяемое на условиях данной Лицензии,         ║
//  ║   предоставляется "КАК ЕСТЬ" и любые явные или неявные ГАРАНТИИ ОТВЕРГАЮТСЯ.    ║
//  ║   Информацию об основных правах и ограничениях,                                 ║
//  ║   применяемых к определенному языку согласно Лицензии,                          ║
//  ║   вы можете найти в данной Лицензии.                                            ║
//  ║                                                                                 ║
//  ╚═════════════════════════════════════════════════════════════════════════════════╝

namespace Universe.IO.Security.Principal.Impersonation
{
    /// <summary>
    /// Specifies the type of login used.
    /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa378184.aspx
    /// </summary>
    public enum LogonType
    {
        /// <summary>
        /// Этот тип входа в систему предназначен для пользователей, которые будут использовать компьютер в интерактивном режиме, например, если пользователь входит в систему.
        /// включается терминальным сервером, удаленной оболочкой или аналогичным процессом. Этот тип входа требует дополнительных затрат на кэширование.
        /// информация для входа в систему для отключенных операций; поэтому это не подходит для некоторых клиент-серверных приложений,
        /// например, почтовый сервер.
        /// </summary>
        Interactive = 2,

        /// <summary>
        // Этот тип входа в систему предназначен для высокопроизводительных серверов для аутентификации паролей в виде открытого текста.
        /// Функция LogonUser не кэширует учетные данные для этого типа входа в систему.
        /// </summary>
        Network = 3,

        /// <summary>
        /// Этот тип входа в систему предназначен для серверов пакетной обработки, где процессы могут выполняться от имени пользователя.
        /// без их прямого вмешательства. Этот тип также подходит для высокопроизводительных серверов, которые обрабатывают много
        /// одновременные попытки аутентификации с открытым текстом, например, на почтовых или веб-серверах.
        /// </summary>
        Batch = 4,

        /// <summary>
        /// Указывает на вход в систему по типу службы. Для предоставленной учетной записи должна быть включена привилегия службы.
        /// </summary>
        Service = 5,

        /// <summary>
        /// GINA больше не поддерживаются.
        /// Windows Server 2003 и Windows XP: Этот тип входа предназначен для библиотек DLL GINA, которые регистрируют пользователей, которые будут
        /// в интерактивном режиме с помощью компьютера. Этот тип входа в систему может создавать уникальную запись аудита, которая показывает, когда
        /// рабочая станция разблокирована.
        /// </summary>
        Unlock = 7,

        /// <summary>
        /// Этот тип входа в систему сохраняет имя и пароль в пакете аутентификации, что позволяет серверу
        /// для подключения к другим сетевым серверам, выдавая себя за клиента. Сервер может принимать открытый текст
        /// учетные данные от клиента, вызовите LogonUser, убедитесь, что пользователь может получить доступ к системе по сети,
        /// и по-прежнему общаться с другими серверами.
        /// </summary>
        NetworkCleartext = 8,

        /// <summary>
        /// Этот тип входа в систему позволяет вызывающему абоненту клонировать свой текущий токен и указывать новые учетные данные для исходящих подключений.
        /// Новый сеанс входа в систему имеет тот же локальный идентификатор, но использует другие учетные данные для других сетевых подключений.
        /// Этот тип входа в систему поддерживается только поставщиком входа LOGON32_PROVIDER_WINNT50.
        /// </summary>
        NewCredentials = 9,
    }
}
