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

using System.Collections.Generic;
using Universe.Helpers.Extensions;

namespace Universe.DataAccess.Models
{
    /// <summary>
    ///     Сущность в БД
    /// <author>Alex Envision</author>
    /// </summary>
    public class Entity
    {
        public long Id { get; set; }

        private readonly Dictionary<string, ForeignKeyEntity> _entityPropStorage = new Dictionary<string, ForeignKeyEntity>();

        public void SetEntity<T>(string idPropName, T value) where T : Entity
        {
            var entityProp = _entityPropStorage.GetOrCreate(idPropName, () => new ForeignKeyEntity());
            entityProp.Entity = value;
            entityProp.Id = value?.Id;
        }

        public T GetEntity<T>(string idPropName) where T : Entity
        {
            var entityProp = _entityPropStorage.GetOrCreate(idPropName, () => new ForeignKeyEntity());
            return entityProp.Entity as T;
        }

        public void SetEntityId(string idPropName, long? value)
        {
            var entityProp = _entityPropStorage.GetOrCreate(idPropName, () => new ForeignKeyEntity());
            entityProp.Id = value;
            if (entityProp.Id == null)
                entityProp.Entity = null;

            if (entityProp.Entity?.Id != entityProp.Id)
                entityProp.Entity = null;
        }

        public long? GetEntityId(string idPropName)
        {
            var entityProp = _entityPropStorage.GetOrCreate(idPropName, () => new ForeignKeyEntity());
            if (entityProp.Entity != null)
                return entityProp.Entity.Id;

            return entityProp.Id;
        }

        public long GetEntityIdNotNullable(string idPropName)
        {
            return GetEntityId(idPropName) ?? 0;
        }

        public class ForeignKeyEntity
        {
            public Entity Entity { get; set; }

            public long? Id { get; set; }
        }
    }
}