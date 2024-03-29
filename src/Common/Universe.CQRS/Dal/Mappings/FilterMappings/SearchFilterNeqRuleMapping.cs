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

using System;
using AutoMapper;
using Universe.CQRS.Dal.Mappings.Extensions;
using Universe.CQRS.Dal.Mappings.Framework;
using Universe.CQRS.Models.Condition;
using Universe.CQRS.Models.Filter;

namespace Universe.CQRS.Dal.Mappings.FilterMappings
{
    /// <summary>
    /// <author>Alex Envision</author>
    /// </summary>
    internal sealed class SearchFilterNeqRuleMapping : AutoMap<NeqConfiguration, SearchFilterRule>
    {
        protected override void Configure(IMappingExpression<NeqConfiguration, SearchFilterRule> config)
        {
            base.Configure(config);
            config.Map(x => x.FieldName, x => GetFieldName(x.LeftOperand));
            config.Map(x => x.ValueSelected, x => GetValue(x.RightOperand));
            config.Map(x => x.FilterTypeName, x => ConvertOperator(x.Operator));
        }

        private string GetFieldName(IArgumentConfiguration operand)
        {
            var fieldConfig = operand as FieldArgumentConfiguration;
            var name = fieldConfig?.Field?.SpFieldName;
            return name;
        }

        private string GetValue(IArgumentConfiguration operand)
        {
            var valueConfig = operand as ValueArgumentConfiguration;
            var value = valueConfig?.Expression.Replace("'", "");
            return value;
        }

        private string ConvertOperator(string oper)
        {
            Enum.TryParse<FieldFilterTypes>(oper, true, out var result);
            return result.ToString();
        }
    }
}