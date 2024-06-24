﻿using B2BApp.Entities.Concrete;
using Core.Models.Concrete;
using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace B2BApp.Business.Abstract
{
    public interface ISubeService
    {
        void addSube(Sube sube);
        void updateSube(Sube sube, string subeId);
        void deleteSube(ObjectId objectId);
        Result<ICollection<Sube>> getAll();
        Result<Sube> getSubeById(ObjectId objectId);
    }
}